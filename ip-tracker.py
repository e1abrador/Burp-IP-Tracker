from burp import IBurpExtender, ITab
from javax.swing import JPanel, JTable, JScrollPane, BoxLayout, Timer
from javax.swing.table import DefaultTableModel
import java.awt.Dimension as Dimension
import java.lang.System as System
import java.util.Date as Date
import java.text.SimpleDateFormat as SimpleDateFormat
import java.net.URL as URL
import java.io.BufferedReader as BufferedReader
import java.io.InputStreamReader as InputStreamReader
import java.awt.event.ActionListener as ActionListener

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.callbacks.setExtensionName("IP Logger")
        self.ui = IPLoggerUI()
        self.callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "IP Logger"

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

        self.lastIP = None
        self.timer = Timer(1, IPCheckAction(self))
        self.timer.start()

    def log_current_ip(self):
        try:
            url = URL("https://api.ipify.org")
            connection = url.openConnection()
            reader = BufferedReader(InputStreamReader(connection.getInputStream()))
            ip = reader.readLine()
            reader.close()

            currentTime = SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(Date(System.currentTimeMillis()))

            # If the fetched IP is different from the last recorded IP, log it.
            if ip != self.lastIP:
                # If this is not the first IP being logged, update the last detection time for the previous IP.
                if self.lastIP is not None:
                    rowCount = self.model.getRowCount()
                    # Set the "Last Detection Time" for the previous IP entry.
                    self.model.setValueAt(currentTime, rowCount - 1, 2)

                # Add the new IP with the detection time and an empty "Last Detection Time".
                self.model.addRow([ip, currentTime, ""])
                self.lastIP = ip

        except Exception as e:
            self.model.addRow(["Error fetching IP", str(e), ""])

class IPCheckAction(ActionListener):
    def __init__(self, ipLoggerUI):
        self.ipLoggerUI = ipLoggerUI

    def actionPerformed(self, event):
        self.ipLoggerUI.log_current_ip()
