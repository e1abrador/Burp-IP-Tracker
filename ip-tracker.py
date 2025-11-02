from burp import IBurpExtender, ITab, IExtensionStateListener, IHttpListener
from javax.swing import JPanel, JTable, JScrollPane, BoxLayout, JButton, JFileChooser, BorderFactory
from javax.swing import JLabel, SwingConstants, Box, JSeparator, JComboBox, JTextField, GroupLayout
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing.border import EmptyBorder, CompoundBorder, TitledBorder
from java.awt import Color, Font, FlowLayout, BorderLayout, Dimension, GridLayout
from java.awt.event import ActionListener, MouseAdapter, MouseEvent
from java.util import Timer, TimerTask
from java.io import File
import java.awt.Dimension as Dimension
import java.lang.System as System
import java.text.SimpleDateFormat as SimpleDateFormat
import java.util.ArrayList as ArrayList
import json
import socket
import struct
import random
import threading
import time

# Clase personalizada para DefaultTableModel
class ReadOnlyTableModel(DefaultTableModel):
    def isCellEditable(self, row, column):
        return False

class BurpExtender(IBurpExtender, IExtensionStateListener, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("IP Tracker")
        
        # Register listeners
        callbacks.registerExtensionStateListener(self)
        callbacks.registerHttpListener(self)
        
        # Initialize persistence
        self.project_file = None
        self.setupProjectState()
        
        # Create UI after we have the project state
        self.ui = IPLoggerUI(callbacks, self)
        callbacks.customizeUiComponent(self.ui.getUiComponent())
        callbacks.addSuiteTab(self.ui)
        
        print "IP Tracker extension loaded successfully"
    
    def extensionUnloaded(self):
        # Save state before unloading
        try:
            self.ui.saveState()
            print "IP Tracker extension unloaded"
        except:
            print "Error saving state during unload"
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # This is where we could extract IP information from HTTP traffic
        # Currently we're using STUN for IP detection, but this could be an alternative
        pass
    
    def setupProjectState(self):
        # Try to get current project identifier
        try:
            # Get a unique identifier for the current project file - using hash of project name or path
            # In a real implementation, you might use a better way to identify the current project
            # For now, we'll just use "default" as a placeholder
            project_id = "default_project"
            self.project_file = project_id
            
            # Load project-specific data if it exists
            project_data = self.callbacks.loadExtensionSetting("ip_tracker_" + project_id)
            if project_data is not None:
                # We have project-specific data, load it as the current data
                self.callbacks.saveExtensionSetting("ip_logs", project_data)
                print "Loaded project-specific IP tracking data"
            else:
                print "No project-specific IP tracking data found"
        except Exception as e:
            print "Error setting up project state:", e
            
class IPLoggerUI(ITab):
    def __init__(self, callbacks, extender):
        self.callbacks = callbacks
        self.extender = extender
        
        # Define colors for a professional look
        self.BACKGROUND_COLOR = Color(245, 245, 247)
        self.HEADER_COLOR = Color(66, 66, 76)
        self.ACCENT_COLOR = Color(88, 157, 246)
        self.BUTTON_COLOR = Color(88, 157, 246)
        self.TEXT_COLOR = Color(50, 50, 50)
        self.ALT_ROW_COLOR = Color(240, 240, 242)
        self.ERROR_COLOR = Color(217, 83, 79)
        self.SUCCESS_COLOR = Color(92, 184, 92)
        
        # Create main panel
        self.panel = JPanel(BorderLayout())
        self.panel.setBackground(self.BACKGROUND_COLOR)
        self.panel.setBorder(EmptyBorder(15, 15, 15, 15))
        
        # Create header panel with logo
        headerPanel = JPanel(BorderLayout())
        headerPanel.setBackground(self.BACKGROUND_COLOR)
        headerPanel.setBorder(EmptyBorder(0, 0, 10, 0))
        
        # Add title
        titleLabel = JLabel("IP Tracker", SwingConstants.LEFT)
        titleLabel.setFont(Font("Arial", Font.BOLD, 20))
        titleLabel.setForeground(self.HEADER_COLOR)
        headerPanel.add(titleLabel, BorderLayout.WEST)
        
        # Add status info
        self.statusLabel = JLabel("Initializing IP tracking...")
        self.statusLabel.setFont(Font("Arial", Font.ITALIC, 12))
        self.statusLabel.setForeground(Color(100, 100, 100))
        headerPanel.add(self.statusLabel, BorderLayout.EAST)
        
        # Add header to main panel
        self.panel.add(headerPanel, BorderLayout.NORTH)
        
        # Create table panel with border
        tablePanel = JPanel(BorderLayout())
        tablePanel.setBackground(self.BACKGROUND_COLOR)
        tablePanel.setBorder(CompoundBorder(
            TitledBorder(BorderFactory.createLineBorder(self.ACCENT_COLOR, 1), 
                         "IP Address History", 
                         TitledBorder.LEFT, 
                         TitledBorder.TOP,
                         Font("Arial", Font.BOLD, 14),
                         self.ACCENT_COLOR),
            EmptyBorder(10, 10, 10, 10)))
        
        # Create table with custom rendering - using our ReadOnlyTableModel class
        self.model = ReadOnlyTableModel(
            ["IP Address", "First Detection Time", "Last Detection Time", "Duration"], 
            0
        )
        
        self.table = JTable(self.model)
        self.table.setRowHeight(28)
        self.table.setFont(Font("Arial", Font.PLAIN, 13))
        self.table.getTableHeader().setFont(Font("Arial", Font.BOLD, 13))
        self.table.getTableHeader().setBackground(self.HEADER_COLOR)
        self.table.getTableHeader().setForeground(Color.WHITE)
        self.table.setShowGrid(False)
        self.table.setIntercellSpacing(Dimension(0, 0))
        self.table.setFillsViewportHeight(True)
        self.table.setSelectionBackground(self.ACCENT_COLOR.brighter())
        self.table.setSelectionForeground(Color.WHITE)
        
        # Custom renderer for alternating row colors
        class CustomCellRenderer(DefaultTableCellRenderer):
            def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
                component = DefaultTableCellRenderer.getTableCellRendererComponent(
                    self, table, value, isSelected, hasFocus, row, column)
                
                if not isSelected:
                    if row % 2 == 0:
                        component.setBackground(Color.WHITE)
                    else:
                        component.setBackground(self.ALT_ROW_COLOR)
                
                component.setBorder(EmptyBorder(5, 10, 5, 10))
                return component
                
        renderer = CustomCellRenderer()
        renderer.ALT_ROW_COLOR = self.ALT_ROW_COLOR
        for i in range(self.table.getColumnCount()):
            self.table.getColumnModel().getColumn(i).setCellRenderer(renderer)
        
        # Set preferred column widths
        self.table.getColumnModel().getColumn(0).setPreferredWidth(150)  # IP
        self.table.getColumnModel().getColumn(1).setPreferredWidth(180)  # First detection
        self.table.getColumnModel().getColumn(2).setPreferredWidth(180)  # Last detection
        self.table.getColumnModel().getColumn(3).setPreferredWidth(120)  # Duration
        
        # Add table to scroll pane
        scrollPane = JScrollPane(self.table)
        scrollPane.setBorder(BorderFactory.createLineBorder(Color.LIGHT_GRAY, 1))
        tablePanel.add(scrollPane, BorderLayout.CENTER)
        
        # Add table panel to main panel
        self.panel.add(tablePanel, BorderLayout.CENTER)
        
        # Create button panel
        buttonPanel = JPanel(BorderLayout())
        buttonPanel.setBackground(self.BACKGROUND_COLOR)
        buttonPanel.setBorder(EmptyBorder(10, 0, 0, 0))
        
        # Create info panel on the left side
        infoPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        infoPanel.setBackground(self.BACKGROUND_COLOR)
        
        # Add version info
        versionLabel = JLabel("v1.2.0")
        versionLabel.setFont(Font("Arial", Font.ITALIC, 11))
        versionLabel.setForeground(Color(120, 120, 120))
        infoPanel.add(versionLabel)
        
        buttonPanel.add(infoPanel, BorderLayout.WEST)
        
        # Create right side panel for buttons
        rightPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
        rightPanel.setBackground(self.BACKGROUND_COLOR)
        
        # Create styled buttons
        self.refreshButton = self.createStyledButton("Refresh Now", "Force an immediate IP check")
        self.refreshButton.addActionListener(RefreshListener(self))
        
        self.exportCSVButton = self.createStyledButton("Export as CSV", "Save IP history to CSV file")
        self.exportCSVButton.addActionListener(ExportListener(self))
        
        self.clearButton = self.createStyledButton("Clear History", "Clear all IP history data")
        self.clearButton.addActionListener(ClearHistoryListener(self))
        
        # Add buttons to right panel
        rightPanel.add(self.refreshButton)
        rightPanel.add(Box.createRigidArea(Dimension(10, 0)))
        rightPanel.add(self.clearButton)
        rightPanel.add(Box.createRigidArea(Dimension(10, 0)))
        rightPanel.add(self.exportCSVButton)
        
        # Add right panel to button panel
        buttonPanel.add(rightPanel, BorderLayout.EAST)
        
        # Add button panel to main panel
        self.panel.add(buttonPanel, BorderLayout.SOUTH)
        
        # Initialize data and timer
        self.last_ip = None
        self.error_count = 0  # Track consecutive errors
        self.auto_save_interval = 30000  # 30 seconds
        
        # Load data (with project awareness)
        self.load_persisted_data()
        
        # Start timers
        self.timer = Timer(True)
        self.timer.scheduleAtFixedRate(IPCheckTask(self), 0, 5000)  # Check every 5 seconds
        self.timer.scheduleAtFixedRate(AutoSaveTask(self), self.auto_save_interval, self.auto_save_interval)  # Auto-save
    
    def createStyledButton(self, text, tooltip):
        button = JButton(text)
        button.setBackground(self.BUTTON_COLOR)
        button.setForeground(Color.WHITE)
        button.setFont(Font("Arial", Font.BOLD, 12))
        button.setFocusPainted(False)
        button.setBorder(BorderFactory.createEmptyBorder(8, 15, 8, 15))
        button.setToolTipText(tooltip)
        
        # Add hover effect
        class ButtonMouseListener(MouseAdapter):
            def mouseEntered(self, e):
                button.setBackground(Color(88, 157, 246).brighter())
                
            def mouseExited(self, e):
                button.setBackground(self.BUTTON_COLOR)
                
        listener = ButtonMouseListener()
        listener.BUTTON_COLOR = self.BUTTON_COLOR
        button.addMouseListener(listener)
        
        return button

    def getTabCaption(self):
        return "IP Tracker"

    def getUiComponent(self):
        return self.panel

    def load_persisted_data(self):
        try:
            persisted_data = self.callbacks.loadExtensionSetting("ip_logs")
            if persisted_data:
                data = json.loads(persisted_data)
                for entry in data:
                    # Skip error entries
                    if entry["ip"].startswith("Error"):
                        continue
                    
                    # Calculate duration if available
                    duration = ""
                    if entry.get("last_detection_time", ""):
                        try:
                            fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
                            first_time = fmt.parse(entry["detection_time"])
                            last_time = fmt.parse(entry["last_detection_time"])
                            diff_ms = last_time.getTime() - first_time.getTime()
                            
                            # Format duration
                            if diff_ms < 60000:  # Less than a minute
                                duration = str(int(diff_ms / 1000)) + " seconds"
                            elif diff_ms < 3600000:  # Less than an hour
                                duration = str(int(diff_ms / 60000)) + " minutes"
                            else:  # Hours or more
                                duration = str(round(diff_ms / 3600000.0, 1)) + " hours"
                        except Exception, e:
                            print "Error calculating duration:", e
                    
                    self.model.addRow([
                        entry["ip"], 
                        entry["detection_time"], 
                        entry.get("last_detection_time", ""),
                        duration
                    ])
                
                if data:
                    # Find last valid IP
                    for entry in reversed(data):
                        if not entry["ip"].startswith("Error"):
                            self.last_ip = entry["ip"]
                            break
            self.updateStatusLabel()
        except Exception, e:
            print "Error loading persisted data:", e
            self.setErrorStatus("Error loading data: " + str(e))

    def saveState(self):
        """Save state for current project"""
        try:
            data = []
            for row in range(self.model.getRowCount()):
                data.append({
                    "ip": str(self.model.getValueAt(row, 0)),
                    "detection_time": str(self.model.getValueAt(row, 1)),
                    "last_detection_time": str(self.model.getValueAt(row, 2)),
                    # Duration is calculated on load, no need to store it
                })
            
            # Save general data
            json_data = json.dumps(data)
            self.callbacks.saveExtensionSetting("ip_logs", json_data)
            
            # Save project-specific data if we have a project identifier
            if self.extender.project_file:
                self.callbacks.saveExtensionSetting(
                    "ip_tracker_" + str(self.extender.project_file), 
                    json_data
                )
                
            # Show autosave indicator briefly (but only if we're visible)
            if hasattr(self, 'panel') and self.panel.isShowing():
                self.showStatusMessage("Data saved automatically", self.SUCCESS_COLOR, 2000)
        except Exception, e:
            print "Error saving data:", e
            if hasattr(self, 'panel') and self.panel.isShowing():
                self.setErrorStatus("Error saving data: " + str(e))

    def write_to_csv(self, file):
        try:
            writer = open(file.getAbsolutePath(), 'w')
            try:
                # Write header
                headers = []
                for col in range(self.model.getColumnCount()):
                    headers.append(self.model.getColumnName(col))
                writer.write(",".join(headers) + "\n")
                
                # Write data
                for row in range(self.model.getRowCount()):
                    line = [
                        '"' + str(self.model.getValueAt(row, col)).replace('"', '""') + '"'  # Quote each field
                        for col in range(self.model.getColumnCount())
                    ]
                    writer.write(",".join(line) + "\n")
                
                self.showStatusMessage("Export successful: " + file.getName(), self.SUCCESS_COLOR, 3000)
            finally:
                writer.close()
        except Exception, e:
            print "Error writing to CSV file:", e
            self.setErrorStatus("Error exporting to CSV: " + str(e))

    def clear_history(self):
        self.model.setRowCount(0)
        self.last_ip = None
        self.saveState()  # Save the empty state
        self.showStatusMessage("History cleared successfully", self.SUCCESS_COLOR, 3000)

    def log_current_ip(self):
        try:
            # Use STUN to fetch public IP
            ip = self.get_public_ip_via_stun()
            current_time = SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(System.currentTimeMillis())
            
            # Reset error count on success
            self.error_count = 0
            
            if ip != self.last_ip:
                if self.last_ip is not None and self.model.getRowCount() > 0:
                    # Update last detection time for previous IP
                    row_idx = self.model.getRowCount() - 1
                    self.model.setValueAt(current_time, row_idx, 2)
                    
                    # Calculate and update duration
                    try:
                        fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
                        first_time = fmt.parse(str(self.model.getValueAt(row_idx, 1)))
                        last_time = fmt.parse(current_time)
                        diff_ms = last_time.getTime() - first_time.getTime()
                        
                        # Format duration
                        if diff_ms < 60000:  # Less than a minute
                            duration = str(int(diff_ms / 1000)) + " seconds"
                        elif diff_ms < 3600000:  # Less than an hour
                            duration = str(int(diff_ms / 60000)) + " minutes"
                        else:  # Hours or more
                            duration = str(round(diff_ms / 3600000.0, 1)) + " hours"
                            
                        self.model.setValueAt(duration, row_idx, 3)
                    except Exception, e:
                        print "Error calculating duration:", e
                
                # Add new IP to table
                self.model.addRow([ip, current_time, "", ""])
                self.last_ip = ip
                
                # Auto-save
                self.saveState()
                
                # Update status with new IP
                self.showStatusMessage("New IP detected: " + ip, self.ACCENT_COLOR, 5000)
            else:
                self.updateStatusLabel()
                
        except Exception, e:
            # Instead of adding error to table, just show in status
            self.error_count += 1
            self.setErrorStatus("Error fetching IP: " + str(e))
            
            # Log error to console only
            print "Error fetching IP:", e
    
    def setErrorStatus(self, message):
        """Set error message in status label"""
        if hasattr(self, 'statusLabel'):  # Ensure statusLabel exists
            self.statusLabel.setText(message + " (Retrying...)")
            self.statusLabel.setForeground(self.ERROR_COLOR)
    
    def showStatusMessage(self, message, color, duration_ms):
        """Show a temporary status message with custom color"""
        if not hasattr(self, 'statusLabel'):  # Safety check
            return
            
        self.statusLabel.setText(message)
        self.statusLabel.setForeground(color)
        
        # Reset after specified duration
        timer_task = ResetLabelTask(self)
        reset_timer = Timer()
        reset_timer.schedule(timer_task, duration_ms)
    
    def updateStatusLabel(self):
        """Update the status label with default status"""
        if not hasattr(self, 'statusLabel'):  # Safety check
            return
            
        if self.last_ip:
            self.statusLabel.setText("Monitoring IP: " + self.last_ip)
            self.statusLabel.setForeground(Color(100, 100, 100))  # Normal color
        else:
            self.statusLabel.setText("Waiting to detect your public IP address...")
            self.statusLabel.setForeground(Color(100, 100, 100))  # Normal color

    def get_public_ip_via_stun(self, stun_server="stun.l.google.com", stun_port=19302):
        """Get public IP address using STUN protocol"""
        # Try multiple STUN servers if needed
        stun_servers = [
            ("stun1.l.google.com", 19302),
            ("stun.ekiga.net", 3478),
            ("stun.ideasip.com", 3478),
            ("stun.voiparound.com", 3478),
        ]
        
        # Start with the default server
        servers_to_try = [(stun_server, stun_port)] + stun_servers
        
        last_error = None
        s = None
        
        for server, port in servers_to_try:
            try:
                if s:
                    try:
                        s.close()
                    except:
                        pass
                        
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(2)  # Timeout for response
                
                # Generate random 16-byte transaction ID
                tid = ''.join(chr(random.randint(0, 255)) for _ in range(16))
                
                # STUN binding request (type 0x0001, length 0)
                request = struct.pack("!HH", 0x0001, 0) + tid
                s.sendto(request, (server, port))
                
                data, addr = s.recvfrom(1024)
                
                # Parse header
                msg_type, msg_len = struct.unpack("!HH", data[:4])
                if msg_type != 0x0101:
                    raise ValueError("Not a STUN binding response")
                if data[4:20] != tid:
                    raise ValueError("Transaction ID mismatch")
                
                # Parse attributes
                pos = 20
                while pos < 20 + msg_len:
                    attr_type, attr_len = struct.unpack("!HH", data[pos:pos+4])
                    pos += 4
                    value = data[pos:pos + attr_len]
                    pos += attr_len
                    
                    # Pad to 4-byte boundary
                    if pos % 4 != 0:
                        pos += 4 - (pos % 4)
                        
                    if attr_type == 0x0001:  # MAPPED-ADDRESS
                        unused, family, port = struct.unpack("!BBH", value[:4])
                        if family == 1:  # IPv4
                            ip_bytes = struct.unpack("!BBBB", value[4:8])
                            ip_address = ".".join(map(str, ip_bytes))
                            
                            # Close the socket before returning
                            try:
                                s.close()
                            except:
                                pass
                                
                            return ip_address
                        # IPv6 (family 2) can be added if needed
                
                raise ValueError("No mapped address attribute found in response")
                
            except Exception, e:
                last_error = e
                continue
        
        # Make sure to close the socket if we're exiting with an error
        if s:
            try:
                s.close()
            except:
                pass
        
        # If we get here, all servers failed
        if last_error:
            raise last_error
        else:
            raise ValueError("All STUN servers failed")

class RefreshListener(ActionListener):
    """Listener for manual refresh button"""
    def __init__(self, ui):
        self.ui = ui
        
    def actionPerformed(self, event):
        # Disable button temporarily
        self.ui.refreshButton.setEnabled(False)
        
        try:
            # Update status
            self.ui.statusLabel.setText("Checking IP address...")
            self.ui.statusLabel.setForeground(self.ui.ACCENT_COLOR)
            
            # Force an IP check
            self.ui.log_current_ip()
            
        finally:
            # Re-enable button after a short delay
            refresh_timer = Timer()
            refresh_timer.schedule(EnableButtonTask(self.ui.refreshButton), 2000)

class EnableButtonTask(TimerTask):
    """Task to re-enable a button after a delay"""
    def __init__(self, button):
        self.button = button
        
    def run(self):
        try:
            self.button.setEnabled(True)
        except:
            pass  # Ignore errors if button no longer exists

class ExportListener(ActionListener):
    """Listener for export CSV button"""
    def __init__(self, ui):
        self.ui = ui
        
    def actionPerformed(self, event):
        chooser = JFileChooser()
        chooser.setDialogTitle("Save IP History as CSV")
        ret = chooser.showSaveDialog(self.ui.panel)
        if ret == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            # Add .csv extension if not present
            if not file.getName().lower().endswith(".csv"):
                file = File(file.getAbsolutePath() + ".csv")
            self.ui.write_to_csv(file)

class ClearHistoryListener(ActionListener):
    """Listener for clear history button"""
    def __init__(self, ui):
        self.ui = ui
        
    def actionPerformed(self, event):
        self.ui.clear_history()

class IPCheckTask(TimerTask):
    """Task to periodically check IP address"""
    def __init__(self, ip_logger_ui):
        self.ip_logger_ui = ip_logger_ui

    def run(self):
        try:
            self.ip_logger_ui.log_current_ip()
        except Exception, e:
            # Capture any errors to prevent the timer from stopping
            print "Error in IP check task:", e

class AutoSaveTask(TimerTask):
    """Task to periodically save state"""
    def __init__(self, ip_logger_ui):
        self.ip_logger_ui = ip_logger_ui

    def run(self):
        try:
            self.ip_logger_ui.saveState()
        except Exception, e:
            # Capture any errors to prevent the timer from stopping
            print "Error in auto-save task:", e

class ResetLabelTask(TimerTask):
    """Task to reset status label after a delay"""
    def __init__(self, ui):
        self.ui = ui
        
    def run(self):
        try:
            if hasattr(self.ui, 'updateStatusLabel'):
                self.ui.updateStatusLabel()
        except Exception, e:
            # Capture any errors
            print "Error in reset label task:", e
