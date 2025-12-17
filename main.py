import sys
import os
import subprocess
import shutil
import json
from PyQt6 import uic
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QFileDialog,
    QMessageBox,
    QCheckBox,
    QListWidgetItem,
)
from groq import Groq

# Read the API key from an environment variable instead of hard-coding it
api_key = os.getenv("GROQ_API_KEY")
if not api_key:
    raise RuntimeError("GROQ_API_KEY environment variable is not set")

client = Groq(api_key=api_key)

pcap_name = ""


def load_protocol_definitions() -> tuple[dict, dict]:
    """
    Load protocol categories and build a flat mapping of name -> filter.
    Falls back to a minimal built-in set if the JSON is missing or invalid.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    json_path = os.path.join(base_dir, "protocols.json")
    categories: dict[str, list[dict]] = {}

    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                categories = json.load(f)
        except Exception:
            categories = {}

    if not categories:
        # Fallback basic set
        categories = {
            "Network & Transport": [
                {"name": "TCP", "filter": "tcp"},
                {"name": "UDP", "filter": "udp"},
                {"name": "ICMP", "filter": "icmp || icmpv6"},
            ],
            "Application": [
                {"name": "HTTP", "filter": "http"},
                {"name": "HTTPS", "filter": "tls || ssl"},
            ],
        }

    flat_filters: dict[str, str] = {}
    for protos in categories.values():
        for proto in protos:
            name = proto.get("name")
            flt = proto.get("filter")
            if name and flt:
                flat_filters[name] = flt

    return categories, flat_filters


PROTOCOL_CATEGORIES, PROTOCOL_FILTERS = load_protocol_definitions()


def ask_ai(prompt: str) -> str:
    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a highly competent cybersecurity and network analysis assistant. "
                        "Write strictly professional, technical responses. "
                        "Do not use emojis, slang, or emotional language. "
                        "Focus on clear logic, concise structure, and practical details. "
                        "If the user is vague, state what assumptions you are making. "
                        "When you want to actually run a tshark command, output it on its own line "
                        "prefixed with 'TSHARK_RUN: ' (without quotes). For example:\n"
                        "TSHARK_RUN: tshark -r pcaps/sample.pcap -Y \"dns\" -V\n"
                        "These lines will be executed automatically by the application. "
                        "Only use this mechanism for safe, non-destructive tshark commands."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"[AI ERROR] {type(e).__name__}: {e}"


class AIWorker(QThread):
    """
    Simple worker that runs ask_ai in a background thread
    so the UI stays responsive.
    """

    finished = pyqtSignal(str)

    def __init__(self, prompt: str, parent=None):
        super().__init__(parent)
        self.prompt = prompt

    def run(self):
        result = ask_ai(self.prompt)
        self.finished.emit(result)


class ScanWorker(QThread):
    """
    Worker that runs a tshark scan on an offline pcap and then asks the AI
    to analyze the summarized output.
    """

    finished = pyqtSignal(str)

    def __init__(
        self,
        pcap_path: str,
        selected_protocols: list[str],
        display_filter: str | None,
        parent=None,
    ):
        super().__init__(parent)
        self.pcap_path = pcap_path
        self.selected_protocols = selected_protocols
        self.display_filter = display_filter

    def run(self):
        # Build tshark command
        cmd = [
            "tshark",
            "-r",
            self.pcap_path,
            "-c",
            "500",  # limit number of packets to keep output manageable
            "-T",
            "fields",
            "-E",
            "separator=,",
            "-e",
            "frame.number",
            "-e",
            "frame.time_relative",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "tcp.srcport",
            "-e",
            "tcp.dstport",
            "-e",
            "udp.srcport",
            "-e",
            "udp.dstport",
            "-e",
            "frame.protocols",
            "-e",
            "_ws.col.Info",
        ]

        if self.display_filter:
            cmd.extend(["-Y", self.display_filter])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
        except Exception as e:
            self.finished.emit(f"[SCAN ERROR] {type(e).__name__}: {e}")
            return

        if result.returncode != 0:
            self.finished.emit(
                f"[SCAN ERROR] tshark exited with {result.returncode}: {result.stderr.strip()}"
            )
            return

        lines = [ln for ln in result.stdout.splitlines() if ln.strip()]
        if not lines:
            self.finished.emit("[SCAN] No packets matched the specified filter.")
            return

        max_lines = 200
        sample_lines = lines[:max_lines]
        sample_text = "\n".join(sample_lines)

        protocols_str = ", ".join(self.selected_protocols) or "ALL"
        filter_str = self.display_filter or "none"

        prompt = (
            "You are a cybersecurity and network analysis assistant.\n"
            "You will be given summarized output from tshark for an offline PCAP capture.\n"
            "Your tasks are:\n"
            "1. Identify likely security issues, anomalies, or CTF-relevant artifacts.\n"
            "2. Prioritize findings by severity (Critical/High/Medium/Low).\n"
            "3. Suggest next investigation steps and concrete display filters or Wireshark views.\n"
            "4. If this looks like CTF traffic, explicitly point out possible flags, credentials, or exfiltration.\n\n"
            f"Selected protocols: {protocols_str}\n"
            f"Display filter used: {filter_str}\n"
            f"PCAP path (for reference only, do not assume access): {self.pcap_path}\n\n"
            "Below are up to the first 200 matching packets from tshark, as CSV lines with the following fields:\n"
            "frame.number, frame.time_relative, ip.src, ip.dst, tcp.srcport, tcp.dstport, "
            "udp.srcport, udp.dstport, frame.protocols, info\n\n"
            f"{sample_text}\n"
        )

        ai_response = ask_ai(prompt)
        self.finished.emit(ai_response)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi("Main.ui", self)
        self.SendBtn.clicked.connect(self.send_text)
        self.DelBtn.clicked.connect(self.clear_input)
        self.ScanBtn.clicked.connect(self.run_scan)
        self.selectAllBtn.clicked.connect(self.select_all_protocols)
        self.tsharkRunBtn.clicked.connect(self.on_tshark_run_clicked)
        self._ai_worker = None
        self._scan_worker = None
        # Protocol selection model
        self.selected_protocols: set[str] = set()
        self._protocol_checkboxes: dict[str, QCheckBox] = {}
        self.init_protocol_ui()

    def init_protocol_ui(self):
        """
        Populate the category combo and build protocol checkboxes from JSON.
        """
        # Fill category combo box
        self.categoryCombo.clear()
        categories = list(PROTOCOL_CATEGORIES.keys())
        categories.sort()
        for cat in categories:
            self.categoryCombo.addItem(cat)

        # Connect signals
        self.categoryCombo.currentTextChanged.connect(self.load_protocol_category)

        # Clear any statically defined checkboxes in the UI
        layout = self.protocol_list.layout()
        if layout is not None:
            while layout.count():
                item = layout.takeAt(0)
                w = item.widget()
                if w is not None:
                    w.deleteLater()

        # Load initial category (first in sorted list)
        if categories:
            self.load_protocol_category(categories[0])

    def load_protocol_category(self, category: str):
        """
        Show checkboxes for the selected category, keeping previous selections.
        """
        layout = self.protocol_list.layout()
        if layout is None:
            return

        # Clear previous widgets
        while layout.count():
            item = layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()

        self._protocol_checkboxes.clear()

        protos = PROTOCOL_CATEGORIES.get(category, [])
        for proto in protos:
            name = proto.get("name")
            if not name:
                continue
            cb = QCheckBox(name, self.protocol_list)
            cb.setChecked(name in self.selected_protocols)
            cb.stateChanged.connect(self.on_protocol_checkbox_changed)
            layout.addWidget(cb)
            self._protocol_checkboxes[name] = cb

        # Add a stretch so checkboxes are at the top
        layout.addStretch(1)

        self.update_selected_list_widget()

    def on_protocol_checkbox_changed(self, state: int):
        """
        Track selections in a set and update the 'selected' list.
        """
        cb = self.sender()
        if not isinstance(cb, QCheckBox):
            return
        name = cb.text()
        if cb.isChecked():
            self.selected_protocols.add(name)
        else:
            self.selected_protocols.discard(name)
        self.update_selected_list_widget()

    def update_selected_list_widget(self):
        """
        Reflect currently selected protocols in the QListWidget.
        """
        self.selectedList.clear()
        for name in sorted(self.selected_protocols):
            item = QListWidgetItem(name)
            self.selectedList.addItem(item)

    # -------- tshark command execution --------

    def on_tshark_run_clicked(self):
        """
        Run a tshark command typed by the user in the UI.
        """
        cmd = self.tsharkCommandEdit.text().strip()
        if not cmd:
            return
        self.run_tshark_command(cmd)

    def run_tshark_command(self, cmd: str):
        """
        Execute a tshark command in a subprocess and show the output.
        Only commands starting with 'tshark' are allowed.
        """
        if not cmd.startswith("tshark"):
            QMessageBox.warning(
                self,
                "Invalid command",
                "For safety, only commands starting with 'tshark' are allowed.",
            )
            return

        self.Ai_output.append(f"[TSHARK] $ {cmd}")
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
            )
        except Exception as e:
            self.Ai_output.append(f"[TSHARK ERROR] {type(e).__name__}: {e}")
            return

        stdout = result.stdout or ""
        stderr = result.stderr or ""

        if stdout:
            self.Ai_output.append(stdout)
        if stderr:
            self.Ai_output.append(f"[TSHARK STDERR]\n{stderr}")

        # Send tshark output back to the AI for further analysis
        if stdout:
            # Truncate to avoid sending excessively large outputs
            max_chars = 8000
            trimmed = stdout[:max_chars]
            prompt = (
                "You are analyzing network traffic. Below is the raw output of a tshark command "
                "that was just executed. Continue the investigation based on this data. "
                "Focus on concrete findings, anomalies, and next steps. "
                "Here is the command and its (possibly truncated) output:\n\n"
                f"Command:\n{cmd}\n\n"
                "Output:\n"
                f"{trimmed}\n"
            )
            # Run this in the background so the UI stays responsive
            self._ai_worker = AIWorker(prompt, self)
            self._ai_worker.finished.connect(self.on_ai_finished)
            self._ai_worker.start()

    def run_ai_suggested_tshark_commands(self, response: str):
        """
        Parse AI output for lines starting with 'TSHARK_RUN:' and execute them.
        """
        for line in response.splitlines():
            stripped = line.strip()
            if stripped.startswith("TSHARK_RUN:"):
                cmd = stripped[len("TSHARK_RUN:") :].strip()
                if cmd:
                    self.run_tshark_command(cmd)

    def send_text(self):
        text = self.input_box.toPlainText().strip()
        if not text:
            return

        # Optional: disable the button while the request is running
        self.SendBtn.setEnabled(False)
        self.Ai_output.append("[INFO] Sending prompt to AI...")

        # Start the AI worker thread
        self._ai_worker = AIWorker(text, self)
        self._ai_worker.finished.connect(self.on_ai_finished)
        self._ai_worker.start()

    def on_ai_finished(self, response: str):
        self.Ai_output.append(response)
        # Execute any tshark commands explicitly requested by the AI
        self.run_ai_suggested_tshark_commands(response)
        self.SendBtn.setEnabled(True)
        # Allow the worker to be garbage-collected
        self._ai_worker = None

    def clear_input(self):
        self.input_box.clear()

    def prot_select(self):
        """
        Return selected protocol names and a combined tshark display filter.
        """
        selected = sorted(self.selected_protocols)
        # Build display filter based on selected protocols
        parts = []
        for name in selected:
            filt = PROTOCOL_FILTERS.get(name)
            if filt:
                parts.append(f"({filt})")
        display_filter = " or ".join(parts) if parts else None
        return selected, display_filter

    def run_scan(self):
        """
        Trigger an offline PCAP scan using tshark and AI analysis.
        """
        pcap_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select PCAP file",
            "",
            "PCAP files (*.pcap *.pcapng);;All files (*)",
        )
        if not pcap_path:
            return

        # Ensure local pcaps directory exists and move the selected file there
        base_dir = os.path.dirname(os.path.abspath(__file__))
        pcaps_dir = os.path.join(base_dir, "pcaps")
        os.makedirs(pcaps_dir, exist_ok=True)

        original_name = os.path.basename(pcap_path)
        dest_path = os.path.join(pcaps_dir, original_name)

        try:
            if os.path.abspath(pcap_path) != os.path.abspath(dest_path):
                shutil.move(pcap_path, dest_path)
        except Exception as e:
            QMessageBox.warning(
                self,
                "PCAP move error",
                f"Could not move capture file:\n{e}",
            )
            dest_path = pcap_path  # fall back to original path

        # Indicate in the AI output which type of capture was loaded
        ext = os.path.splitext(dest_path)[1].lower()
        if ext == ".pcapng":
            type_str = "PCAPNG"
        elif ext == ".pcap":
            type_str = "PCAP"
        else:
            type_str = "Capture file"

        self.Ai_output.append(
            f"[INFO] {type_str} loaded: {os.path.basename(dest_path)}"
        )

        selected_protocols, display_filter = self.prot_select()
        if not selected_protocols:
            QMessageBox.warning(
                self,
                "No protocols selected",
                "Please select at least one protocol to scan.",
            )
            return

        self.ScanBtn.setEnabled(False)
        self.Ai_output.append(
            f"[INFO] Running offline scan on {dest_path} "
            f"with protocols: {', '.join(selected_protocols)}"
        )

        self._scan_worker = ScanWorker(
            pcap_path=dest_path,
            selected_protocols=selected_protocols,
            display_filter=display_filter,
            parent=self,
        )
        self._scan_worker.finished.connect(self.on_scan_finished)
        self._scan_worker.start()

    def on_scan_finished(self, response: str):
        self.Ai_output.append(response)
        self.ScanBtn.setEnabled(True)
        self._scan_worker = None

    def select_all_protocols(self):
        """
        Set all protocol checkboxes to checked.
        """
        # Select every known protocol across all categories
        self.selected_protocols = {
            proto["name"]
            for protos in PROTOCOL_CATEGORIES.values()
            for proto in protos
            if proto.get("name")
        }

        # Update currently visible checkboxes
        for name, cb in self._protocol_checkboxes.items():
            cb.blockSignals(True)
            cb.setChecked(True)
            cb.blockSignals(False)

        self.update_selected_list_widget()
       

def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
