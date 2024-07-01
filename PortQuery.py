import socket
from concurrent.futures import ThreadPoolExecutor
from scapy.all import sr1, IP, UDP, ICMP
from PyQt5.QtWidgets import (QApplication, QWidget, QLabel, QLineEdit,
                             QPushButton, QMessageBox, QVBoxLayout, QTextEdit,
                             QProgressBar, QFileDialog, QComboBox, QSpinBox,
                             QGridLayout, QGroupBox, QHBoxLayout, QTableWidget,
                             QTableWidgetItem, QHeaderView, QMenu, QDialog, QVBoxLayout,
                             QLabel, QLineEdit, QPushButton, QComboBox, QSpinBox, QDialogButtonBox,
                             QFormLayout, QMessageBox, QCheckBox, QStatusBar, QSizePolicy)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QIcon, QFont
import csv
import ipaddress
import logging
import time
import threading

# 命令行窗口执行 ‘netstat -a -n’ 可查看开放的端口，验证结果
# 常量定义
DEFAULT_TIMEOUT = 1
DEFAULT_MAX_THREADS = 100
PORT_RANGE_MIN = 1
PORT_RANGE_MAX = 65535

# 日志记录设置
logging.basicConfig(filename='port_scanner.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def scan_tcp_port(target_host, port, scan_type, timeout):
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.settimeout(timeout)
    try:
        if scan_type == 'SYN':
            tcp_sock.connect((target_host, port))
        elif scan_type == 'NULL':
            # NULL扫描示例实现（发送没有任何标志位的TCP包）
            tcp_sock.sendto(b'', (target_host, port))
        elif scan_type == 'XMAS':
            # XMAS扫描示例实现（发送带有FIN、PSH和URG标志位的TCP包）
            tcp_sock.sendto(b'\x29', (target_host, port))
        return True  # 端口开放
    except (socket.timeout, socket.error):
        return False  # 端口关闭
    finally:
        tcp_sock.close()


def scan_udp_port(target_host, port, timeout):
    packet = IP(dst=target_host) / UDP(dport=port)
    response = sr1(packet, timeout=timeout, verbose=False)
    if response is None:
        return True  # 没有响应可能表示端口开放
    elif response.haslayer(ICMP):
        if response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code == 3:
            return False  # 收到ICMP“端口不可达”消息（端口关闭）
    return True


class PortScannerThread(QThread):
    progress_signal = pyqtSignal(int)
    result_signal = pyqtSignal(list, list)
    error_signal = pyqtSignal(str)
    speed_signal = pyqtSignal(float)  # 添加 speed_signal 信号

    def __init__(self, target_host, start_port, end_port, scan_type, max_threads=DEFAULT_MAX_THREADS,
                 timeout=DEFAULT_TIMEOUT, retry=1):
        super().__init__()
        self.target_host = target_host
        self.start_port = start_port
        self.end_port = end_port
        self.scan_type = scan_type
        self.max_threads = max_threads
        self.timeout = timeout
        self.retry = retry
        self.start_time = 0
        self.end_time = 0
        self.total_scanned_ports = 0
        self.lock = threading.Lock()

    def run(self):
        open_tcp_ports = set()
        open_udp_ports = set()
        total_ports = self.end_port - self.start_port + 1
        progress = 0
        self.start_time = time.time()
        self.scanned_ports_count = 0  # Add a variable to track scanned ports count
        try:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for port in range(self.start_port, self.end_port + 1):
                    for _ in range(self.retry):
                        futures.append(executor.submit(
                            lambda p: open_tcp_ports.add(p) if scan_tcp_port(self.target_host, p, self.scan_type,
                                                                             self.timeout) else None, port))
                        futures.append(executor.submit(
                            lambda p: open_udp_ports.add(p) if scan_udp_port(self.target_host, p,
                                                                             self.timeout) else None, port))

                for future in futures:
                    future.result()
                    with self.lock:
                        self.total_scanned_ports += 1
                        self.scanned_ports_count += 1  # Increment scanned ports count
                    self.progress_signal.emit(int((self.total_scanned_ports / (total_ports * 2 * self.retry)) * 100))
                    progress += 1
                    self.progress_signal.emit(int((progress / (total_ports * 2 * self.retry)) * 100))
                    scan_duration = time.time() - self.start_time
                    scan_speed = self.total_scanned_ports / scan_duration if scan_duration > 0 else 0
                    self.speed_signal.emit(scan_speed)  # Send scan speed signal

            self.result_signal.emit(sorted(list(open_tcp_ports)), sorted(list(open_udp_ports)))

        except Exception as e:
            self.error_signal.emit(str(e))
            logging.error(f'扫描错误: {e}', exc_info=True)

        finally:
            self.end_time = time.time()
            scan_duration = self.end_time - self.start_time
            scan_speed = self.total_scanned_ports / scan_duration if scan_duration > 0 else 0
            logging.info(f'扫描速度: {scan_speed} 端口/秒')


class PortScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('端口扫描器')
        self.resize(800, 600)
        self.setWindowIcon(QIcon('images/image1.png'))  # 添加窗口图标

        # 创建各控件
        self.label_host = QLabel('目标主机:')
        self.entry_host = QLineEdit()
        self.entry_host.setPlaceholderText("例如: 192.168.1.1")

        self.label_start_port = QLabel('起始端口:')
        self.entry_start_port = QLineEdit()
        self.entry_start_port.setPlaceholderText("例如: 1")

        self.label_end_port = QLabel('结束端口:')
        self.entry_end_port = QLineEdit()
        self.entry_end_port.setPlaceholderText("例如: 65535")

        self.label_scan_type = QLabel('扫描类型:')
        self.combo_scan_type = QComboBox()
        self.combo_scan_type.addItems(['SYN', 'NULL', 'XMAS'])

        self.label_threads = QLabel('最大线程数:')
        self.spin_threads = QSpinBox()
        self.spin_threads.setRange(1, 200)
        self.spin_threads.setValue(100)

        self.label_timeout = QLabel('超时时间(秒):')
        self.spin_timeout = QSpinBox()
        self.spin_timeout.setRange(1, 60)
        self.spin_timeout.setValue(1)

        self.label_retry = QLabel('重试次数:')
        self.spin_retry = QSpinBox()
        self.spin_retry.setRange(1, 5)
        self.spin_retry.setValue(1)

        self.check_export_json = QCheckBox('导出为JSON')
        self.check_export_xml = QCheckBox('导出为XML')

        self.button_scan = QPushButton('扫描')
        self.button_scan.setIcon(QIcon('images/image2.png'))  # 添加按钮图标
        self.button_scan.clicked.connect(self.start_scan)

        self.label_speed = QLabel('扫描速度:')
        self.label_speed_value = QLabel('0 端口/秒')

        self.label_result = QLabel('扫描结果:')
        self.table_result = QTableWidget()
        self.table_result.setColumnCount(3)
        self.table_result.setHorizontalHeaderLabels(['端口号', '协议', '状态'])
        header = self.table_result.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Stretch)

        self.label_progress = QLabel('扫描进度:')
        self.progress_bar = QProgressBar()
        self.progress_percentage = QLabel('0%')

        self.label_statistics = QLabel("统计信息: ")
        self.label_statistics_value = QLabel('TCP 端口数: 0 , UDP 端口数: 0 , 总端口数: 0 ')

        self.button_export = QPushButton('导出结果')
        self.button_export.setIcon(QIcon('images/image3.png'))  # 添加按钮图标
        self.button_export.clicked.connect(self.export_results)
        self.button_export.setEnabled(False)

        # 状态栏
        self.status_bar = QStatusBar()

        self.thread = None  # 在这里初始化为None

        # 布局设置
        self.layout_ui()

        if self.thread is not None:
            self.thread.speed_signal.connect(self.update_speed)

        # 设置整体布局
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.scan_group)
        main_layout.addWidget(self.result_group)
        main_layout.addWidget(self.status_bar)

        self.setLayout(main_layout)

        # 应用样式表
        self.apply_styles()

    def layout_ui(self):
        # 扫描设置分组框
        self.scan_group = QGroupBox('扫描设置')
        scan_layout = QGridLayout()

        scan_layout.addWidget(self.label_host, 0, 0)
        scan_layout.addWidget(self.entry_host, 0, 1, 1, 3)

        scan_layout.addWidget(self.label_start_port, 1, 0)
        scan_layout.addWidget(self.entry_start_port, 1, 1)
        scan_layout.addWidget(self.label_end_port, 1, 2)
        scan_layout.addWidget(self.entry_end_port, 1, 3)

        scan_layout.addWidget(self.label_scan_type, 2, 0)
        scan_layout.addWidget(self.combo_scan_type, 2, 1)

        scan_layout.addWidget(self.label_threads, 3, 0)
        scan_layout.addWidget(self.spin_threads, 3, 1)
        scan_layout.addWidget(self.label_timeout, 3, 2)
        scan_layout.addWidget(self.spin_timeout, 3, 3)

        scan_layout.addWidget(self.label_retry, 4, 0)
        scan_layout.addWidget(self.spin_retry, 4, 1)

        scan_layout.addWidget(self.check_export_json, 5, 0)
        scan_layout.addWidget(self.check_export_xml, 5, 1)

        scan_layout.addWidget(self.button_scan, 6, 0, 1, 4)

        self.scan_group.setLayout(scan_layout)

        # 扫描结果分组框
        self.result_group = QGroupBox('扫描结果')
        result_layout = QVBoxLayout()

        progress_layout = QHBoxLayout()
        progress_layout.addWidget(self.label_progress)
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.progress_percentage)

        # 添加速度布局
        speed_layout = QHBoxLayout()
        speed_layout.addWidget(self.label_speed)
        speed_layout.addWidget(self.label_speed_value)

        # 添加统计布局
        statistics_layout = QHBoxLayout()
        statistics_layout.addWidget(self.label_statistics)
        statistics_layout.addStretch(1)  # 添加伸缩项
        statistics_layout.addWidget(self.label_statistics_value)
        statistics_layout.addStretch(1)  # 添加伸缩项


        result_layout.addLayout(progress_layout)
        result_layout.addLayout(speed_layout)  # 添加显示速度的布局
        result_layout.addLayout(statistics_layout)  # 添加统计信息的布局
        result_layout.addWidget(self.table_result)
        result_layout.addWidget(self.button_export)

        self.result_group.setLayout(result_layout)

        # 设置表格控件的大小策略
        self.table_result.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

    def apply_styles(self):
        # 样式表
        self.setStyleSheet("""
            QWidget {
                background-color: #F0F0F0;
                font-family: Arial;
                font-size: 14px;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #B0B0B0;
                border-radius: 5px;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 10px;
            }
            QLabel {
                color: #333333;
            }
            QLineEdit, QComboBox, QSpinBox {
                border: 1px solid #B0B0B0;
                border-radius: 3px;
                padding: 5px;
                background-color: #FFFFFF;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px 20px;
                text-align: center;
                text-decoration: none;
                display: inline-block;
                font-size: 14px;
                margin: 4px 2px;
                border-radius: 5px;
                transition-duration: 0.4s;
                cursor: pointer;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QTableWidget {
                background-color: #FFFFFF;
                border: 1px solid #B0B0B0;
                gridline-color: #E0E0E0;
                selection-background-color: #B0E0E6;
                selection-color: #000000;
            }
            QProgressBar {
                text-align: center;
                color: white;
                background-color: #B0B0B0;
                border: none;
                border-radius: 5px;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                border-radius: 5px;
            }
            QStatusBar {
                background-color: #E0E0E0;
                border: 1px solid #B0B0B0;
                border-radius: 3px;
                padding: 5px;
            }
        """)

    def update_speed(self, speed):
        print(f"Received speed signal: {speed}")
        self.label_speed_value.setText(f'{speed:.2f} 端口/秒')

    def set_scan_button_enabled(self, enabled):
        self.button_scan.setEnabled(enabled)

    def start_scan(self):
        target_host = self.entry_host.text()
        start_port_str = self.entry_start_port.text()
        end_port_str = self.entry_end_port.text()
        scan_type = self.combo_scan_type.currentText()
        max_threads = self.spin_threads.value()
        timeout = self.spin_timeout.value()
        retry = self.spin_retry.value()

        if not target_host:
            QMessageBox.critical(self, '错误', '请输入目标主机.')
            return

        try:
            ipaddress.ip_address(target_host)
        except ValueError:
            QMessageBox.critical(self, '错误', '无效的目标主机地址.')
            return

        if not start_port_str or not end_port_str:
            QMessageBox.critical(self, '错误', '请输入起始和结束端口.')
            return

        try:
            start_port = int(start_port_str)
            end_port = int(end_port_str)
            if start_port < PORT_RANGE_MIN or end_port > PORT_RANGE_MAX or start_port > end_port:
                raise ValueError
        except ValueError:
            QMessageBox.critical(self, '错误', '无效的端口号，请输入1到65535之间的整数，且结束端口应大于等于起始端口.')
            return

        if self.thread is None:
            self.set_scan_button_enabled(False)  # 禁用扫描按钮
            self.thread = PortScannerThread(target_host, start_port, end_port, scan_type, max_threads, timeout, retry)
            self.thread.progress_signal.connect(self.update_progress)
            self.thread.result_signal.connect(self.display_results)
            self.thread.error_signal.connect(self.display_error)
            self.thread.speed_signal.connect(self.update_speed)
            self.thread.finished.connect(self.on_scan_finished)  # 在扫描完成后执行操作
            self.thread.start()
        else:
            QMessageBox.information(self, '提示', '扫描已经在进行中，请等待当前扫描完成后再开始新的扫描。')

        self.table_result.setRowCount(0)
        self.progress_bar.setValue(0)
        self.button_export.setEnabled(False)

    def on_scan_finished(self):
        # 扫描完成后将 self.thread 设置为 None
        self.thread = None
        self.set_scan_button_enabled(True)  # 在扫描完成后启用扫描按钮
    def update_progress(self, progress):
        self.progress_bar.setValue(progress)
        self.progress_percentage.setText(f'{progress}%')

    def display_results(self, open_tcp_ports, open_udp_ports):
        self.update_statistics(open_tcp_ports, open_udp_ports)
        self.table_result.setRowCount(len(open_tcp_ports) + len(open_udp_ports))
        row = 0
        for port in open_tcp_ports:
            self.table_result.setItem(row, 0, QTableWidgetItem(str(port)))
            self.table_result.setItem(row, 1, QTableWidgetItem('TCP'))
            self.table_result.setItem(row, 2, QTableWidgetItem('Open'))
            row += 1
        for port in open_udp_ports:
            self.table_result.setItem(row, 0, QTableWidgetItem(str(port)))
            self.table_result.setItem(row, 1, QTableWidgetItem('UDP'))
            self.table_result.setItem(row, 2, QTableWidgetItem('Open'))
            row += 1

        self.label_progress.setText('扫描进度: 100%')
        self.button_export.setEnabled(True)
        logging.info(f'扫描结果: TCP {open_tcp_ports}, UDP {open_udp_ports}')

    def display_error(self, error_message):
        QMessageBox.critical(self, '错误', f'扫描过程中发生错误: {error_message}')
        self.progress_bar.setValue(0)
        self.progress_percentage.setText('0%')
        self.button_export.setEnabled(False)
        logging.error(f'扫描错误: {error_message}')

    def export_results(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(self, "保存扫描结果", "", "CSV文件 (*.csv);;所有文件 (*)", options=options)
        if file_path:
            try:
                with open(file_path, mode='w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(['端口号', '协议', '状态'])
                    for row in range(self.table_result.rowCount()):
                        port = self.table_result.item(row, 0).text()
                        protocol = self.table_result.item(row, 1).text()
                        status = self.table_result.item(row, 2).text()
                        writer.writerow([port, protocol, status])
                QMessageBox.information(self, '成功', '扫描结果已成功导出.')
                logging.info(f'扫描结果导出至: {file_path}')
            except Exception as e:
                QMessageBox.critical(self, '错误', f'保存扫描结果时发生错误: {e}')
                logging.error(f'保存扫描结果时发生错误: {e}', exc_info=True)

        # 导出为JSON
        if self.check_export_json.isChecked():
            json_path, _ = QFileDialog.getSaveFileName(self, "保存扫描结果 (JSON)", "", "JSON文件 (*.json);;所有文件 (*)", options=options)
            if json_path:
                try:
                    import json
                    result_dict = {}
                    for row in range(self.table_result.rowCount()):
                        port = self.table_result.item(row, 0).text()
                        protocol = self.table_result.item(row, 1).text()
                        status = self.table_result.item(row, 2).text()
                        if protocol not in result_dict:
                            result_dict[protocol] = []
                        result_dict[protocol].append({'port': port, 'status': status})
                    with open(json_path, 'w') as json_file:
                        json.dump(result_dict, json_file)
                    QMessageBox.information(self, '成功', '扫描结果已成功导出为JSON.')
                    logging.info(f'扫描结果导出为JSON至: {json_path}')
                except Exception as e:
                    QMessageBox.critical(self, '错误', f'保存扫描结果为JSON时发生错误: {e}')
                    logging.error(f'保存扫描结果为JSON时发生错误: {e}', exc_info=True)

        # 导出为XML
        if self.check_export_xml.isChecked():
            xml_path, _ = QFileDialog.getSaveFileName(self, "保存扫描结果 (XML)", "", "XML文件 (*.xml);;所有文件 (*)", options=options)
            if xml_path:
                try:
                    import xml.etree.ElementTree as ET
                    root = ET.Element("ports")
                    for row in range(self.table_result.rowCount()):
                        port = self.table_result.item(row, 0).text()
                        protocol = self.table_result.item(row, 1).text()
                        status = self.table_result.item(row, 2).text()
                        port_element = ET.SubElement(root, "port")
                        port_element.set("number", port)
                        port_element.set("protocol", protocol)
                        port_element.set("status", status)
                    tree = ET.ElementTree(root)
                    tree.write(xml_path)
                    QMessageBox.information(self, '成功', '扫描结果已成功导出为XML.')
                    logging.info(f'扫描结果导出为XML至: {xml_path}')
                except Exception as e:
                    QMessageBox.critical(self, '错误', f'保存扫描结果为XML时发生错误: {e}')
                    logging.error(f'保存扫描结果为XML时发生错误: {e}', exc_info=True)

    def update_statistics(self, open_tcp_ports, open_udp_ports):
        total_tcp = len(open_tcp_ports)
        total_udp = len(open_udp_ports)
        total_ports = total_tcp + total_udp
        self.label_statistics_value.setText(f"TCP 端口数: {total_tcp}, UDP 端口数: {total_udp}, 总端口数: {total_ports}")

    def closeEvent(self, event):
        reply = QMessageBox.question(self, '退出', '确定要退出吗?',
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()


if __name__ == '__main__':
    import sys

    app = QApplication(sys.argv)
    scanner = PortScannerApp()
    scanner.show()
    sys.exit(app.exec_())


