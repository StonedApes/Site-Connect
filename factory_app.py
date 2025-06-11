import sys
import requests
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, QPushButton, QComboBox, QHBoxLayout, QLineEdit, QInputDialog, QLabel, QMessageBox
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

class FactoryApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Factory Order Management")
        self.setGeometry(100, 100, 900, 600)

        self.api_url = "http://localhost:5001/api"
        self.company_id = None
        self.username = None
        self.logged_in = False

        # Set global font
        self.setFont(QFont("Arial", 12))

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        self.company_login()

    def company_login(self):
        try:
            response = requests.get(f"{self.api_url}/companies", timeout=5)
            if response.status_code != 200:
                QInputDialog.getText(self, "Error", f"Failed to fetch companies. Status code: {response.status_code}. Press OK to retry.")
                self.company_login()
                return

            try:
                companies = response.json().get("companies", [])
            except ValueError as e:
                QInputDialog.getText(self, "Error", f"Invalid response from server: {e}. Press OK to retry.")
                self.company_login()
                return

            if not companies:
                QInputDialog.getText(self, "Error", "No companies found. Press OK to exit.")
                sys.exit()

            company_name, ok = QInputDialog.getText(self, "Company Login", "Enter company name:")
            if not ok:
                sys.exit()

            for company in companies:
                if company["name"] == company_name:
                    self.company_id = company["id"]
                    self.user_login()
                    return

            QInputDialog.getText(self, "Error", "Company not found. Press OK to retry.")
            self.company_login()
        except requests.exceptions.ConnectionError:
            QInputDialog.getText(self, "Error", "Cannot connect to server. Ensure the Flask server is running at http://localhost:5000. Press OK to retry.")
            self.company_login()
        except requests.exceptions.Timeout:
            QInputDialog.getText(self, "Error", "Request timed out. Ensure the Flask server is running and responsive. Press OK to retry.")
            self.company_login()
        except Exception as e:
            QInputDialog.getText(self, "Error", f"Unexpected error: {e}. Press OK to retry.")
            self.company_login()

    def user_login(self):
        while not self.logged_in:
            username, ok = QInputDialog.getText(self, "Login", "Username:")
            if not ok:
                sys.exit()
            password, ok = QInputDialog.getText(self, "Login", "Password:", QLineEdit.Password)
            if not ok:
                sys.exit()

            try:
                response = requests.post(f"{self.api_url}/login", data={"username": username, "password": password, "company_id": self.company_id}, timeout=5)
                if response.status_code == 200:
                    self.username = username
                    self.logged_in = True
                    self.setup_ui()
                else:
                    QInputDialog.getText(self, "Error", f"Invalid credentials (Status code: {response.status_code}). Press OK to retry.")
            except requests.exceptions.ConnectionError:
                QInputDialog.getText(self, "Error", "Cannot connect to server. Ensure the Flask server is running at http://localhost:5000. Press OK to retry.")
            except requests.exceptions.Timeout:
                QInputDialog.getText(self, "Error", "Request timed out. Ensure the Flask server is running and responsive. Press OK to retry.")
            except Exception as e:
                QInputDialog.getText(self, "Error", f"Connection error: {e}. Press OK to retry.")

    def setup_ui(self):
        # Status label
        self.status_label = QLabel(f"Logged in as {self.username} (Company ID: {self.company_id})")
        self.status_label.setStyleSheet("padding: 10px; background-color: #e9ecef; border-radius: 5px;")
        self.layout.addWidget(self.status_label)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels(["ID", "Item", "Quantity", "Site ID", "Status", "Trailer ID", "Comments", "Timestamp"])
        self.table.setColumnWidth(4, 150)
        self.table.setColumnWidth(5, 150)
        self.table.setColumnWidth(6, 200)
        self.table.setColumnWidth(7, 200)
        self.table.setStyleSheet("alternate-background-color: #f8f9fa; background-color: #ffffff;")
        self.layout.addWidget(self.table)

        # Controls
        self.controls_layout = QVBoxLayout()
        self.status_layout = QHBoxLayout()
        self.status_combo = QComboBox()
        self.status_combo.addItems(["Pending", "Received", "In Production", "Shipped"])
        self.status_combo.setStyleSheet("padding: 5px;")
        self.status_layout.addWidget(self.status_combo)

        self.comments_input = QLineEdit()
        self.comments_input.setPlaceholderText("Add comments...")
        self.comments_input.setStyleSheet("padding: 5px; border-radius: 5px;")
        self.controls_layout.addWidget(self.comments_input)

        self.delay_input = QLineEdit()
        self.delay_input.setPlaceholderText("Report delay (e.g., Traffic, 2 hours)...")
        self.delay_input.setStyleSheet("padding: 5px; border-radius: 5px;")
        self.controls_layout.addWidget(self.delay_input)

        self.update_button = QPushButton("Update Order")
        self.update_button.clicked.connect(self.update_order)
        self.update_button.setStyleSheet("background-color: #007bff; color: white; padding: 10px; border-radius: 5px; font-weight: bold;")
        self.update_button.setCursor(Qt.PointingHandCursor)
        self.controls_layout.addWidget(self.update_button)

        self.layout.addLayout(self.status_layout)
        self.layout.addLayout(self.controls_layout)

        self.refresh_button = QPushButton("Refresh Orders")
        self.refresh_button.clicked.connect(self.load_orders)
        self.refresh_button.setStyleSheet("background-color: #28a745; color: white; padding: 10px; border-radius: 5px; font-weight: bold;")
        self.refresh_button.setCursor(Qt.PointingHandCursor)
        self.layout.addWidget(self.refresh_button)

        self.load_orders()

    def load_orders(self):
        try:
            response = requests.get(f"{self.api_url}/orders", params={"company_id": self.company_id}, timeout=5)
            if response.status_code != 200:
                QMessageBox.critical(self, "Error", f"Failed to load orders. Status code: {response.status_code}")
                return

            try:
                orders = response.json().get("orders", [])
            except ValueError as e:
                QMessageBox.critical(self, "Error", f"Invalid response from server: {e}")
                return

            self.table.setRowCount(len(orders))
            for i, order in enumerate(orders):
                self.table.setItem(i, 0, QTableWidgetItem(str(order["id"])))
                self.table.setItem(i, 1, QTableWidgetItem(order["item"]))
                self.table.setItem(i, 2, QTableWidgetItem(str(order["quantity"])))
                self.table.setItem(i, 3, QTableWidgetItem(order["site_id"]))
                self.table.setItem(i, 4, QTableWidgetItem(order["status"]))
                self.table.setItem(i, 5, QTableWidgetItem(order["trailer_id"] or ""))
                self.table.setItem(i, 6, QTableWidgetItem(order["comments"] or ""))
                self.table.setItem(i, 7, QTableWidgetItem(order["timestamp"]))
        except requests.exceptions.ConnectionError:
            QMessageBox.critical(self, "Error", "Cannot connect to server. Ensure the Flask server is running at http://localhost:5000.")
        except requests.exceptions.Timeout:
            QMessageBox.critical(self, "Error", "Request timed out. Ensure the Flask server is running and responsive.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load orders: {e}")

    def update_order(self):
        selected = self.table.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Warning", "Please select an order to update.")
            return

        row = selected[0].row()
        order_id = self.table.item(row, 0).text()
        new_status = self.status_combo.currentText()
        comments = self.comments_input.text()
        delay_notification = self.delay_input.text()

        try:
            response = requests.post(f"{self.api_url}/update_order", json={
                "order_id": order_id,
                "status": new_status,
                "comments": comments,
                "delay_notification": delay_notification,
                "company_id": self.company_id
            }, timeout=5)
            if response.status_code == 200:
                QMessageBox.information(self, "Success", "Order updated successfully!")
                self.load_orders()
                self.comments_input.clear()
                self.delay_input.clear()
            else:
                QMessageBox.critical(self, "Error", f"Failed to update order. Status code: {response.status_code}")
        except requests.exceptions.ConnectionError:
            QMessageBox.critical(self, "Error", "Cannot connect to server. Ensure the Flask server is running at http://localhost:5000.")
        except requests.exceptions.Timeout:
            QMessageBox.critical(self, "Error", "Request timed out. Ensure the Flask server is running and responsive.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to update order: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FactoryApp()
    window.show()
    sys.exit(app.exec_())