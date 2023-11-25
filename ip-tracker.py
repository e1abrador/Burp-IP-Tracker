import java.awt.Dimension as Dimension
import java.lang.System as System
import java.net.URL as URL
import java.text.SimpleDateFormat as SimpleDateFormat
import java.util.Date as Date
from burp import IBurpExtender, ITab
from java.awt.event import ActionListener
from java.io import FileWriter, FileReader, BufferedReader, InputStreamReader
from javax.swing import JPanel, JTable, JScrollPane, BoxLayout, JButton, JFileChooser, Timer
from javax.swing.table import DefaultTableModel


class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.callbacks.setExtensionName("IP Tracker")
        self.ui = IPLoggerUI()
        self.callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "IP Tracker"

    def getUiComponent(self):
        return self.ui.panel


class IPLoggerUI:
    def __init__(self):
        self.panel = JPanel()
        self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))
        self.model = DefaultTableModel(["IP Address", "Detection Time", "Last Detection Time"], 0)
        self.table = JTable(self.model)
        self.table.setPreferredScrollableViewportSize(Dimension(500, 100))
        self.table.setFillsViewportHeight(True)
        scrollPane = JScrollPane(self.table)
        self.panel.add(scrollPane)

        # Save button
        self.saveButton = JButton("Save Log", actionPerformed=self.save_log)
        self.panel.add(self.saveButton)

        # Load button
        self.loadButton = JButton("Load Log", actionPerformed=self.load_log)
        self.panel.add(self.loadButton)

        # Export as CSV button
        self.exportCSVButton = JButton("Export as CSV", actionPerformed=self.export_to_csv)
        self.panel.add(self.exportCSVButton)

        self.lastIP = None
        self.timer = Timer(1000, IPCheckAction(self))  # Adjusted the timer interval to 1000 ms
        self.timer.start()

    def save_log(self, event):
        chooser = JFileChooser()
        ret = chooser.showSaveDialog(self.panel)
        if ret == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            self.write_to_file(file)

    def load_log(self, event):
        chooser = JFileChooser()
        ret = chooser.showOpenDialog(self.panel)
        if ret == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            self.read_from_file(file)
            if not self.timer.isRunning():
                self.timer.start()

    def write_to_file(self, file):
        try:
            writer = FileWriter(file)
            for row in range(self.model.getRowCount()):
                for col in range(self.model.getColumnCount()):
                    writer.write(str(self.model.getValueAt(row, col)) + "\t")
                writer.write("\n")
            writer.close()
        except Exception as e:
            print("Error writing to file:", e)

    def read_from_file(self, file):
        try:
            self.model.setRowCount(0)
            reader = BufferedReader(FileReader(file))
            line = reader.readLine()
            lastLine = None
            while line is not None:
                data = line.split("\t")
                if len(data) >= 3:
                    self.model.addRow(data[:3])
                    lastLine = data
                line = reader.readLine()
            reader.close()
            if lastLine is not None:
                self.lastIP = lastLine[0]
        except Exception as e:
            print("Error reading from file:", e)

    def export_to_csv(self, event):
        chooser = JFileChooser()
        ret = chooser.showSaveDialog(self.panel)
        if ret == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            self.write_to_csv(file)

    def write_to_csv(self, file):
        try:
            writer = FileWriter(file)
            for row in range(self.model.getRowCount()):
                line = [
                    str(self.model.getValueAt(row, col))
                    for col in range(self.model.getColumnCount())
                ]
                writer.write(",".join(line) + "\n")
            writer.close()
        except Exception as e:
            print("Error writing to CSV file:", e)

    def log_current_ip(self):
        try:
            url = URL("https://api.ipify.org")
            connection = url.openConnection()
            reader = BufferedReader(InputStreamReader(connection.getInputStream()))
            ip = reader.readLine()
            reader.close()

            currentTime = SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(Date(System.currentTimeMillis()))

            if ip != self.lastIP:
                if self.lastIP is not None:
                    rowCount = self.model.getRowCount()
                    self.model.setValueAt(currentTime, rowCount - 1, 2)
                self.model.addRow([ip, currentTime, ""])
                self.lastIP = ip

        except Exception as e:
            self.model.addRow(["Error fetching IP", str(e), ""])


class IPCheckAction(ActionListener):
    def __init__(self, ipLoggerUI):
        self.ipLoggerUI = ipLoggerUI

    def actionPerformed(self, event):
        self.ipLoggerUI.log_current_ip()
