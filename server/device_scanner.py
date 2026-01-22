#!/usr/bin/env python3
"""
Network Device Scanner - Discover all devices connected to the network
Identifies device types: iOS, Android, Windows, Mac, Linux, Routers, IoT devices
"""

import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
import socket
import struct
import os
import re
import json

try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[WARNING] Scapy not available for device scanning")

# MAC address vendor prefixes for device identification
MAC_VENDORS = {
    # Apple devices
    'apple': ['00:03:93', '00:05:02', '00:0a:27', '00:0a:95', '00:0d:93', '00:10:fa', '00:11:24', 
              '00:13:72', '00:14:51', '00:16:cb', '00:17:f2', '00:19:e3', '00:1b:63', '00:1c:b3',
              '00:1d:4f', '00:1e:52', '00:1e:c2', '00:1f:5b', '00:1f:f3', '00:21:e9', '00:22:41',
              '00:23:12', '00:23:32', '00:23:6c', '00:23:df', '00:24:36', '00:25:00', '00:25:4b',
              '00:25:bc', '00:26:08', '00:26:4a', '00:26:b0', '00:26:bb', '00:30:65', '00:3e:e1',
              '00:50:e4', '00:61:71', '00:88:65', '00:c6:10', '00:cd:fe', '00:f4:b9', '00:f7:6f',
              '04:0c:ce', '04:15:52', '04:1e:64', '04:26:65', '04:48:9a', '04:4b:ed', '04:54:53',
              '04:69:f8', '04:db:56', '04:e5:36', '04:f1:3e', '04:f7:e4', '08:00:07', '08:66:98',
              '08:6d:41', '08:70:45', '0c:3e:9f', '0c:4d:e9', '0c:74:c2', '0c:77:1a', '10:40:f3',
              '10:41:7f', '10:93:e9', '10:9a:dd', '10:dd:b1', '14:10:9f', '14:5a:05', '14:8f:c6',
              '14:99:e2', '18:34:51', '18:3d:a2', '18:65:90', '18:af:61', '18:e7:f4', '1c:1a:c0',
              '1c:36:bb', '1c:ab:a7', '20:3c:ae', '20:78:f0', '20:a2:e4', '20:ab:37', '20:c9:d0',
              '24:1e:eb', '24:24:0e', '24:a0:74', '24:ab:81', '24:f0:94', '24:f6:77', '28:37:37',
              '28:5a:eb', '28:6a:ba', '28:cf:da', '28:cf:e9', '28:e0:2c', '28:e1:4c', '2c:1f:23',
              '2c:3a:e8', '2c:b4:3a', '2c:be:08', '30:10:e4', '30:90:ab', '30:f7:c5', '34:12:f9',
              '34:15:9e', '34:36:3b', '34:a3:95', '34:c0:59', '34:e2:fd', '38:0f:4a', '38:48:4c',
              '3c:07:54', '3c:2e:f9', '3c:a9:f4', '40:30:04', '40:33:1a', '40:3c:fc', '40:4d:7f',
              '40:a6:d9', '40:b3:95', '40:cb:c0', '44:2a:60', '44:4c:0c', '44:d8:84', '44:fb:42',
              '48:43:7c', '48:60:bc', '48:74:6e', '48:a1:95', '48:d7:05', '4c:3c:16', '4c:57:ca',
              '4c:7c:5f', '4c:8d:79', '50:1a:c5', '50:32:37', '50:7a:55', '50:b7:c3', '50:ea:d6',
              '54:26:96', '54:4e:90', '54:72:4f', '54:80:1d', '54:9f:13', '54:ea:a8', '54:ee:75',
              '58:1f:aa', '58:40:4e', '58:55:ca', '58:b0:35', '5c:59:48', '5c:95:ae', '5c:96:9d',
              '5c:f9:38', '60:33:4b', '60:69:44', '60:92:3a', '60:c5:47', '60:fa:cd', '60:fb:42',
              '64:20:0c', '64:9a:be', '64:a3:cb', '64:b0:a6', '64:e6:82', '68:09:27', '68:5b:35',
              '68:96:7b', '68:a8:6d', '68:db:f5', '68:fe:f7', '6c:19:c0', '6c:40:08', '6c:72:e7',
              '6c:94:66', '6c:96:cf', '6c:ab:31', '70:11:24', '70:48:0f', '70:56:81', '70:cd:60',
              '70:de:e2', '70:ec:e4', '74:1b:b2', '74:81:14', '74:e1:b6', '74:e2:f5', '78:31:c1',
              '78:67:d7', '78:7b:8a', '78:88:6d', '78:a3:e4', '78:ca:39', '78:d7:5f', '78:fd:94',
              '7c:01:91', '7c:11:be', '7c:6d:f8', '7c:c3:a1', '7c:d1:c3', '7c:f0:5f', '80:49:71',
              '80:92:9f', '80:e6:50', '84:38:35', '84:85:06', '84:89:ad', '84:fc:fe', '88:1f:a1',
              '88:53:95', '88:63:df', '88:66:5a', '88:ae:07', '88:cb:87', '88:e8:7f', '8c:00:6d',
              '8c:2d:aa', '8c:58:77', '8c:7b:9d', '8c:7c:92', '8c:85:90', '8c:8e:f2', '90:27:e4',
              '90:72:40', '90:84:0d', '90:8d:6c', '90:b0:ed', '90:b2:1f', '94:94:26', '94:e9:6a',
              '94:f6:a3', '98:01:a7', '98:03:d8', '98:5a:eb', '98:b8:e3', '98:d6:bb', '98:e0:d9',
              '98:f0:ab', '98:fe:94', '9c:04:eb', '9c:20:7b', '9c:35:eb', '9c:f4:8e', 'a0:99:9b',
              'a0:d7:95', 'a4:5e:60', 'a4:67:06', 'a4:b1:97', 'a4:c3:61', 'a4:d1:8c', 'a4:d9:31',
              'a8:20:66', 'a8:5b:78', 'a8:66:7f', 'a8:86:dd', 'a8:88:08', 'a8:96:8a', 'a8:be:27',
              'a8:fa:d8', 'ac:29:3a', 'ac:3c:0b', 'ac:61:ea', 'ac:87:a3', 'ac:bc:32', 'ac:cf:5c',
              'ac:de:48', 'b0:19:c6', 'b0:34:95', 'b0:65:bd', 'b0:70:2d', 'b0:9f:ba', 'b4:18:d1',
              'b4:8b:19', 'b4:f0:ab', 'b4:f6:1c', 'b8:09:8a', 'b8:17:c2', 'b8:41:a4', 'b8:44:d9',
              'b8:53:ac', 'b8:78:2e', 'b8:8d:12', 'b8:c1:11', 'b8:c7:5d', 'b8:e8:56', 'b8:f6:b1',
              'bc:3b:af', 'bc:52:b7', 'bc:67:1c', 'bc:6c:21', 'bc:92:6b', 'bc:9f:ef', 'c0:1a:da',
              'c0:63:94', 'c0:84:7d', 'c0:9f:42', 'c0:cc:f8', 'c0:ce:cd', 'c0:d0:12', 'c4:2c:03',
              'c8:1e:e7', 'c8:2a:14', 'c8:33:4b', 'c8:69:cd', 'c8:6f:1d', 'c8:85:50', 'c8:bc:c8',
              'c8:e0:eb', 'cc:08:8d', 'cc:25:ef', 'cc:29:f5', 'cc:44:63', 'cc:78:5f', 'cc:c7:60',
              'd0:03:4b', 'd0:23:db', 'd0:33:11', 'd0:4f:7e', 'd0:81:7a', 'd0:a6:37', 'd0:e1:40',
              'd4:61:9d', 'd4:90:9c', 'd4:a3:3d', 'd4:dc:cd', 'd4:f4:6f', 'd8:00:4d', 'd8:1d:72',
              'd8:30:62', 'd8:96:85', 'd8:9e:3f', 'd8:a2:5e', 'd8:bb:2c', 'd8:cf:9c', 'dc:0c:5c',
              'dc:2b:2a', 'dc:2b:61', 'dc:37:18', 'dc:56:e7', 'dc:86:d8', 'dc:9b:9c', 'dc:a4:ca',
              'dc:a9:04', 'dc:d3:a2', 'e0:5f:45', 'e0:66:78', 'e0:ac:cb', 'e0:b5:2d', 'e0:b9:a5',
              'e0:c9:7a', 'e0:f8:47', 'e4:25:e7', 'e4:8b:7f', 'e4:9a:79', 'e4:c6:3d', 'e4:ce:8f',
              'e8:04:0b', 'e8:06:88', 'e8:2a:ea', 'e8:40:f2', 'e8:80:2e', 'e8:b2:ac', 'ec:35:86',
              'ec:85:2f', 'f0:18:98', 'f0:24:75', 'f0:5c:19', 'f0:98:9d', 'f0:99:b6', 'f0:b4:79',
              'f0:c3:71', 'f0:cb:a1', 'f0:d1:a9', 'f0:db:e2', 'f0:dc:e2', 'f0:f6:1c', 'f4:0f:24',
              'f4:1b:a1', 'f4:37:b7', 'f4:5c:89', 'f4:f1:5a', 'f4:f9:51', 'f8:1e:df', 'f8:27:93',
              'f8:95:c7', 'fc:25:3f', 'fc:64:ba', 'fc:e9:98', 'fc:fc:48',
              # Latest Apple MAC prefixes (2023-2025)
              '00:88:65', '14:7d:da', '1c:69:a5', '20:ee:28', '28:5a:3a', '2c:54:cf', '30:d9:d9',
              '34:6f:24', '38:ca:da', '3c:e0:72', '40:ed:00', '44:85:00', '48:e7:da', '4c:20:b8',
              '50:de:06', '54:2a:a4', '58:96:1d', '5c:8a:38', '60:8c:4a', '64:cf:0d', '68:54:fd',
              '6c:94:f8', '70:a2:b3', '74:d4:35', '78:c1:a7', '7c:50:79', '80:92:40', '84:a1:34',
              '88:66:a5', '8c:85:80', '90:9c:4a', '94:bf:c4', '98:35:cb', '9c:fc:01', 'a0:78:17',
              'a4:83:e7', 'a8:51:ab', 'ac:e4:b5', 'b0:52:16', 'b4:f1:da', 'b8:78:26', 'bc:d0:74',
              'c0:1a:da', 'c4:b3:01', 'c8:89:f3', 'cc:d2:81', 'd0:c5:f3', 'd4:61:da', 'd8:8f:76',
              'dc:a9:71', 'e0:05:c5', 'e4:90:7e', 'e8:9f:80', 'ec:f4:51', 'f0:2f:74', 'f4:d4:88',
              'f8:ff:c2', 'fc:18:3c'],
    
    # Android manufacturers
    'samsung': ['00:12:fb', '00:13:77', '00:15:99', '00:15:b9', '00:16:32', '00:16:6b', '00:16:6c',
                '00:17:c9', '00:17:d5', '00:18:af', '00:1a:8a', '00:1b:98', '00:1c:43', '00:1d:25',
                '00:1d:f6', '00:1e:7d', '00:1f:cc', '00:21:19', '00:21:4c', '00:23:39', '00:23:d6',
                '00:23:d7', '00:24:54', '00:24:90', '00:24:91', '00:24:e9', '00:25:38', '00:25:66',
                '00:26:37', '1c:86:9a', 'a0:21:95', 'a0:75:91', 'a4:08:ea', 'a8:a1:95', 'ac:36:13', 'b4:07:f9',
                'bc:20:ba', 'c0:bd:d1', 'cc:3a:61', 'd0:22:be', 'd0:66:7b', 'd4:87:d8', 'd8:57:ef',
                'dc:71:44', 'e4:12:1d', 'e4:40:e2', 'e8:03:9a', 'e8:50:8b', 'e8:e5:d6', 'ec:1d:8b',
                'f0:25:b7', 'f0:e7:7e', 'f4:09:d8', 'f4:7b:5e', 'f8:04:2e', 'f8:d0:bd'],
    'xiaomi': ['00:9e:c8', '04:cf:8c', '14:f6:5a', '18:59:36', '28:6c:07', '34:80:b3', '34:ce:00',
               '50:8f:4c', '64:09:80', '68:df:dd', '6c:fa:89', '74:23:44', '78:02:f8', '84:46:93',
               '8c:be:be', '98:fa:e3', 'a0:86:c6', 'ac:c1:ee', 'ac:f7:f3', 'b0:e2:35', 'b4:0b:44',
               'c4:0b:cb', 'd0:7e:28', 'd4:61:fe', 'dc:d9:ae', 'f0:b4:29', 'f4:8b:32', 'f8:a4:5f'],
    'huawei': ['00:1e:10', '00:25:68', '00:46:4b', '00:66:4b', '00:9a:cd', '00:e0:fc', '04:02:1f',
               '04:c0:6f', '08:19:a6', '0c:37:dc', '0c:96:bf', '10:1f:74', '18:68:cb', '20:08:ed',
               '20:76:00', '28:31:52', '2c:ab:a4', '34:6b:d3', '40:4d:8e', '48:46:fb', '48:7d:2e',
               '4c:54:99', '50:01:bb', '54:25:ea', '58:2a:f7', '60:de:44', '64:3e:8c', '68:3e:34',
               '6c:4a:85', '6c:96:d7', '74:a7:8e', '78:d7:52', '84:a8:e4', '88:28:b3', '9c:28:ef',
               'a4:71:74', 'a8:7c:01', 'b4:30:52', 'b8:08:d7', 'bc:25:e0', 'c0:18:03', 'c4:f0:81',
               'c8:14:79', 'cc:96:a0', 'd0:7a:b5', 'd4:6a:a8', 'd8:49:0b', 'dc:d9:16', 'e0:19:1d',
               'e4:d3:32', 'f4:c7:14', 'f8:e7:1e'],
    'google': ['00:1a:11', '3c:5a:b4', '54:60:09', '68:c4:4d', '6c:ad:f8', '84:3a:4b', 'ac:37:43',
               'c4:43:8f', 'd4:f5:13', 'dc:a6:32', 'f4:f5:e8'],
    
    # Windows/PC manufacturers
    'dell': ['00:06:5b', '00:08:74', '00:0b:db', '00:0c:f1', '00:0d:56', '00:0f:1f', '00:11:43',
             '00:12:3f', '00:13:72', '00:14:22', '00:15:c5', '00:18:8b', '00:19:b9', '00:1a:a0',
             '00:1c:23', '00:1d:09', '00:1e:4f', '00:21:70', '00:21:9b', '00:22:19', '00:23:ae',
             '00:24:e8', '00:25:64', '00:26:b9', '18:03:73', '18:66:da', '18:a9:05', '1c:40:24',
             '20:47:47', '24:b6:fd', '28:c8:25', '34:17:eb', '34:e6:d7', '44:a8:42', '4c:76:25',
             '50:9a:4c', '5c:26:0a', '5c:f9:dd', '74:86:7a', '78:2b:cb', '78:45:c4', '80:18:44',
             '84:2b:2b', '84:7b:eb', '90:b1:1c', 'a4:ba:db', 'b0:83:fe', 'b8:2a:72', 'b8:ac:6f',
             'bc:30:5b', 'c8:1f:66', 'd0:67:e5', 'd4:81:d7', 'd4:ae:52', 'd4:be:d9', 'e0:db:55',
             'e4:54:e8', 'f0:1f:af', 'f0:4d:a2', 'f8:b1:56', 'f8:bc:12', 'f8:ca:b8'],
    'hp': ['00:01:e6', '00:01:e7', '00:02:a5', '00:04:ea', '00:08:83', '00:0a:57', '00:0e:7f',
           '00:0f:20', '00:10:83', '00:11:0a', '00:12:79', '00:13:21', '00:14:38', '00:14:c2',
           '00:15:60', '00:16:35', '00:17:08', '00:17:a4', '00:18:fe', '00:19:bb', '00:1a:4b',
           '00:1b:78', '00:1c:c4', '00:1e:0b', '00:1f:29', '00:21:5a', '00:22:64', '00:23:7d',
           '00:24:81', '00:25:b3', '00:26:55', '08:00:09', '10:1f:74', '14:58:d0', '18:a9:05',
           '1c:c1:de', '2c:27:d7', '2c:41:38', '2c:44:fd', '30:e1:71', '34:64:a9', '38:ea:a7',
           '40:a8:f0', '44:1e:a1', '48:0f:cf', '4c:39:09', '58:20:b1', '64:51:06', '70:5a:0f',
           '78:24:af', '78:e3:b5', '80:c1:6e', '98:4b:e1', '9c:2a:70', 'a0:1d:48', 'a0:8c:fd',
           'a4:5d:36', 'a8:66:7f', 'b4:99:ba', 'b8:ac:6f', 'c8:cb:b8', 'd0:7e:28', 'd4:85:64',
           'd8:9d:67', 'e4:11:5b', 'e8:39:35', 'ec:9a:74', 'f0:de:f1', 'f4:ce:46'],
    'lenovo': ['00:0d:60', '00:13:ce', '00:16:ea', '00:17:c4', '00:18:de', '00:19:d1', '00:1a:6b',
               '00:1b:38', '00:1c:25', '00:1d:72', '00:1e:33', '00:1f:16', '00:21:5c', '00:23:24',
               '00:26:55', '1c:3e:84', '28:d2:44', '30:f9:ed', '40:16:7e', '50:3d:e5', '54:ee:75',
               '5c:f9:dd', '68:f7:28', '6c:ae:8b', '74:e5:43', '78:84:3c', '80:18:44', '88:88:87',
               '8c:ec:4b', '94:65:9c', '9c:b6:54', 'a0:b3:cc', 'a4:4e:31', 'b0:83:fe', 'b8:76:3f',
               'bc:16:65', 'c0:18:85', 'd0:50:99', 'd4:be:d9', 'e4:a7:c5', 'f0:de:f1', 'f8:a9:63'],
    'asus': ['00:01:80', '00:0c:6e', '00:0e:a6', '00:11:2f', '00:13:d4', '00:15:f2', '00:17:31',
             '00:18:f3', '00:19:66', '00:1a:92', '00:1b:fc', '00:1d:60', '00:1e:8c', '00:1f:c6',
             '00:22:15', '00:23:54', '00:24:8c', '00:25:90', '00:26:18', '04:d4:c4', '08:60:6e',
             '0c:9d:92', '10:7b:44', '10:bf:48', '14:dd:a9', '1c:87:2c', '1c:b7:2c', '28:e3:47',
             '30:5a:3a', '38:d5:47', '40:16:7e', '50:46:5d', '54:04:a6', '60:45:cb', '70:4d:7b',
             '74:d0:2b', '78:24:af', '9c:5c:8e', 'a8:5e:45', 'ac:22:0b', 'ac:9e:17', 'b0:6e:bf',
             'bc:ee:7b', 'c8:60:00', 'd0:17:c2', 'd8:50:e6', 'e0:3f:49', 'f0:79:59', 'f4:6d:04'],
    
    # Linux/Raspberry Pi
    'raspberry': ['b8:27:eb', 'dc:a6:32', 'e4:5f:01'],
    
    # Network Equipment / Routers
    'tplink': ['00:27:19', '04:95:e6', '08:57:00', '0c:80:63', '10:fe:ed', '14:cc:20', '18:a6:f7',
               '1c:3b:f3', '20:e5:2a', '24:a4:3c', '28:2c:b2', '2c:30:33', '30:b5:c2', '34:2e:b7',
               '38:2c:4a', '3c:84:6a', '40:16:9f', '44:d9:e7', '48:0e:ec', '4c:ed:fb', '50:c7:bf',
               '54:a7:03', '58:d9:d5', '5c:e9:1e', '60:32:b1', '64:66:b3', '68:72:51', '6c:5a:b0',
               '70:4f:57', '74:da:88', '78:8a:20', '7c:8b:ca', '80:ea:96', '84:16:f9', '88:25:93',
               '8c:a6:df', '90:9a:4a', '94:0c:6d', '98:de:d0', '9c:a2:f4', 'a0:f3:c1', 'a4:2b:b0',
               'a8:40:41', 'ac:84:c6', 'b0:95:75', 'b4:b0:24', 'b8:27:eb', 'bc:46:99', 'c0:25:e9',
               'c4:6e:1f', 'c8:3a:35', 'cc:32:e5', 'd0:76:e7', 'd4:6e:0e', 'd8:07:b6', 'dc:9f:db',
               'e0:28:6d', 'e4:6f:13', 'e8:48:b8', 'ec:08:6b', 'ec:26:ca', 'f0:1c:2d', 'f4:ec:38',
               'f8:1a:67', 'fc:d7:33'],
    
    # Security Cameras / IoT
    'hikvision': ['00:12:41', '04:68:3a', '08:60:6e', '0c:d2:92', '10:40:f3', '14:8d:c7', '18:4e:16',
                  '1c:bb:22', '20:47:ed', '24:0f:9b', '28:57:be', '2c:ab:25', '30:d1:7e', '34:c6:87',
                  '38:0a:94', '3c:7a:8a', '40:ac:bf', '44:19:b6', '48:e1:e9', '4c:bd:8f', '50:30:18',
                  '54:c4:15', '58:1f:28', '5c:f9:dd', '60:44:f7', '64:6e:97', '68:3b:78', '6c:c2:17',
                  '70:4d:7b', '74:95:ec', '78:11:dc', '7c:b7:33', '80:1f:12', '84:25:db', '88:12:4e',
                  '8c:ab:8e', '90:55:de', '94:57:a5', '98:91:21', '9c:8c:d8', 'a0:14:3d', 'a4:14:37',
                  'a8:63:7d', 'ac:cc:8e', 'b0:e1:7e', 'b4:a3:82', 'b8:a4:4f', 'bc:ad:28', 'c0:56:e3',
                  'c4:2f:90', 'c8:1f:66', 'cc:d5:39', 'd0:c6:37', 'd4:6e:5c', 'd8:6c:63', 'dc:d3:21',
                  'e0:31:9c', 'e4:d5:3d', 'e8:ab:fa', 'ec:71:db', 'f0:4d:a2', 'f4:84:8d', 'f8:e0:79',
                  'fc:f5:28'],
}

# Connected devices storage
_connected_devices = {}
_device_history = {}  # All devices seen in last 7 days
_devices_lock = threading.Lock()
_last_scan_time = None
HISTORY_RETENTION_DAYS = 7

# Persistent storage files
DEVICE_HISTORY_FILE = os.path.join(os.path.dirname(__file__), 'json', 'device_history.json')
CONNECTED_DEVICES_FILE = os.path.join(os.path.dirname(__file__), 'json', 'connected_devices.json')

# Load existing device data on startup
def _load_device_data():
    """Load device history and connected devices from disk"""
    global _device_history, _connected_devices, _last_scan_time
    
    # Load device history
    try:
        if os.path.exists(DEVICE_HISTORY_FILE):
            with open(DEVICE_HISTORY_FILE, 'r') as f:
                _device_history = json.load(f)
            print(f"[DEVICE SCANNER] Loaded {len(_device_history)} devices from history")
    except Exception as e:
        print(f"[WARNING] Could not load device history: {e}")
    
    # Load connected devices
    try:
        if os.path.exists(CONNECTED_DEVICES_FILE):
            with open(CONNECTED_DEVICES_FILE, 'r') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    _connected_devices = data.get('devices', {})
                    _last_scan_time = data.get('last_scan_time')
                else:
                    # Handle legacy/list formats gracefully
                    _connected_devices = {}
                    _last_scan_time = None
            print(f"[DEVICE SCANNER] Loaded {len(_connected_devices)} previously connected devices")
    except Exception as e:
        print(f"[WARNING] Could not load connected devices: {e}")

def _save_device_data():
    """Save device history and connected devices to disk"""
    # Save device history
    try:
        os.makedirs(os.path.dirname(DEVICE_HISTORY_FILE), exist_ok=True)
        with open(DEVICE_HISTORY_FILE, 'w') as f:
            json.dump(_device_history, f, indent=2)
    except Exception as e:
        print(f"[WARNING] Could not save device history: {e}")
    
    # Save connected devices
    try:
        with open(CONNECTED_DEVICES_FILE, 'w') as f:
            json.dump({
                'devices': _connected_devices,
                'last_scan_time': _last_scan_time
            }, f, indent=2)
    except Exception as e:
        print(f"[WARNING] Could not save connected devices: {e}")

# Load data on module import
_load_device_data()

# Import real blocker (ARP spoofing)
try:
    from device_blocker import block_device as _block_device_real
    from device_blocker import unblock_device as _unblock_device_real
    from device_blocker import is_device_blocked as _is_blocked_real
    BLOCKER_AVAILABLE = True
except ImportError:
    BLOCKER_AVAILABLE = False
    print("[WARNING] Device blocker not available")


class DeviceScanner:
    """Scan network to discover connected devices"""
    
    def __init__(self):
        self.running = False
        self.scan_interval = 300  # Scan every 5 minutes
    
    def start(self):
        """Start device scanning"""
        if not SCAPY_AVAILABLE:
            print("[WARNING] Device scanning disabled - scapy not available")
            return
        
        self.running = True
        print("[DEVICE SCANNER] Starting network device discovery...")
        
        # Start scanning thread
        scan_thread = threading.Thread(target=self._scan_loop, daemon=True)
        scan_thread.start()
    
    def stop(self):
        """Stop device scanning"""
        self.running = False
        print("[DEVICE SCANNER] Device scanning stopped")
    
    def _scan_loop(self):
        """Continuous scanning loop"""
        while self.running:
            try:
                self._scan_network()
            except Exception as e:
                print(f"[ERROR] Device scan error: {e}")
            
            # Wait before next scan
            time.sleep(self.scan_interval)
    
    def _scan_network(self):
        """Scan network for connected devices"""
        global _connected_devices, _last_scan_time
        
        try:
            # Get network interface and IP range
            ip_range = self._get_network_range()
            if not ip_range:
                print("[WARNING] Could not determine network range")
                return
            
            print(f"[DEVICE SCANNER] Scanning network: {ip_range}")
            
            # Create ARP request packet
            arp = ARP(pdst=ip_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # Send ARP request and get responses
            conf.verb = 0  # Disable scapy verbosity
            result = srp(packet, timeout=3, retry=2)[0]
            
            devices = {}
            for sent, received in result:
                ip = received.psrc
                mac = received.hwsrc
                
                # Identify device type and vendor
                device_type = self._identify_device(mac)
                vendor = self._get_vendor_name(mac)
                hostname = self._get_hostname(ip)
                
                # Generate friendly name if hostname is unknown
                if hostname == 'Unknown':
                    hostname = self._generate_device_name(ip, mac, device_type, vendor)
                
                # Scan for open ports
                open_ports = self._scan_ports(ip)
                
                devices[mac] = {
                    'ip': ip,
                    'mac': mac,
                    'type': device_type,
                    'vendor': vendor,
                    'hostname': hostname,
                    'open_ports': open_ports,
                    'last_seen': datetime.now().isoformat(),
                    'first_seen': _connected_devices.get(mac, {}).get('first_seen', datetime.now().isoformat())
                }
            
            # Update global device list and history
            with _devices_lock:
                _connected_devices = devices
                _last_scan_time = datetime.now().isoformat()
                
                # Add all devices to history (for 7-day tracking)
                for mac, device in devices.items():
                    _device_history[mac] = device.copy()
                
                # Persist to disk
                _save_device_data()
            
            print(f"[DEVICE SCANNER] Found {len(devices)} devices on network")
            
        except Exception as e:
            print(f"[ERROR] Network scan failed: {e}")
    
    def _get_network_range(self):
        """Get the network IP range to scan"""
        # Check for environment variable override first
        env_range = os.getenv('NETWORK_RANGE')
        if env_range:
            print(f"[DEVICE SCANNER] Using network range from env: {env_range}")
            return env_range
        
        try:
            # Get default gateway
            import subprocess
            import platform
            
            if platform.system() == 'Linux':
                # Try to get network interface and IP
                result = subprocess.check_output(['ip', 'route']).decode()
                for line in result.split('\n'):
                    if 'default' in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            # Get interface
                            interface = parts[4]
                            # Get IP of interface
                            ip_result = subprocess.check_output(['ip', 'addr', 'show', interface]).decode()
                            for ip_line in ip_result.split('\n'):
                                if 'inet ' in ip_line and '127.0.0.1' not in ip_line:
                                    ip_addr = ip_line.strip().split()[1]
                                    # Convert to network range (e.g., 192.168.1.0/24)
                                    base_ip = '.'.join(ip_addr.split('.')[:3]) + '.0/24'
                                    print(f"[DEVICE SCANNER] Auto-detected network range: {base_ip}")
                                    return base_ip
            
            # Fallback: common private network ranges
            print("[DEVICE SCANNER] Using fallback network range: 192.168.1.0/24")
            return '192.168.1.0/24'
            
        except Exception as e:
            print(f"[WARNING] Could not determine network range: {e}")
            return '192.168.1.0/24'  # Default fallback
    
    def _identify_device(self, mac):
        """Identify device type based on MAC address"""
        mac = mac.lower()
        mac_prefix = ':'.join(mac.split(':')[:3])
        
        # Check against known vendors FIRST
        for device_type, prefixes in MAC_VENDORS.items():
            if mac_prefix in [p.lower() for p in prefixes]:
                if device_type == 'apple':
                    return 'iPhone/iPad/Mac'
                elif device_type in ['samsung', 'xiaomi', 'huawei', 'google']:
                    return 'Android Phone'
                elif device_type in ['dell', 'hp', 'lenovo', 'asus']:
                    return 'Windows/Linux PC'
                elif device_type == 'raspberry':
                    return 'Linux (Raspberry Pi)'
                elif device_type == 'tplink':
                    return 'Router/Network'
                elif device_type == 'hikvision':
                    return 'Security Camera'
        
        # Check for randomized MAC address (locally administered bit set)
        # If bit 1 of first octet is set (locally administered), it's likely randomized
        # Second character of first octet: 2, 3, 6, 7, a, b, e, or f
        first_octet = mac.split(':')[0]
        if len(first_octet) == 2:
            second_char = first_octet[1].lower()
            if second_char in ['2', '3', '6', '7', 'a', 'b', 'e', 'f']:
                # This is a randomized MAC address (iOS Private Wi-Fi Address feature)
                return 'iPhone/iPad (Private MAC)'
        
        # Unknown device
        return 'Unknown Device'
    
    def _get_vendor_name(self, mac):
        """Get vendor name from MAC address"""
        mac = mac.lower()
        mac_prefix = ':'.join(mac.split(':')[:3])
        
        # Check against known vendors
        for vendor_name, prefixes in MAC_VENDORS.items():
            if mac_prefix in [p.lower() for p in prefixes]:
                return vendor_name.capitalize()
        
        # Check for randomized MAC
        first_octet = mac.split(':')[0]
        if len(first_octet) == 2:
            second_char = first_octet[1].lower()
            if second_char in ['2', '3', '6', '7', 'a', 'b', 'e', 'f']:
                return 'Apple (Randomized)'
        
        return 'Unknown'
    
    def _generate_device_name(self, ip, mac, device_type, vendor):
        """Generate a friendly device name when hostname is unknown"""
        # Get last octet of IP for uniqueness
        ip_suffix = ip.split('.')[-1]
        
        # Create name based on vendor and device type
        if 'iPhone' in device_type or 'iPad' in device_type or 'Private MAC' in device_type:
            return f"iPhone-{ip_suffix}"
        elif vendor != 'Unknown' and 'Randomized' not in vendor:
            if vendor.lower() == 'apple':
                return f"Apple-{ip_suffix}"
            elif vendor.lower() in ['samsung', 'xiaomi', 'huawei', 'google']:
                return f"{vendor}-Phone-{ip_suffix}"
            elif vendor.lower() in ['dell', 'hp', 'lenovo', 'asus']:
                return f"{vendor}-PC-{ip_suffix}"
            elif vendor.lower() == 'raspberry':
                return f"RaspberryPi-{ip_suffix}"
            elif vendor.lower() == 'tplink':
                return f"TP-Link-Router-{ip_suffix}"
            elif vendor.lower() == 'hikvision':
                return f"Hikvision-Camera-{ip_suffix}"
            else:
                return f"{vendor}-Device-{ip_suffix}"
        
        # Fallback to device type
        if device_type != 'Unknown Device':
            type_short = device_type.replace('/', '-').replace(' ', '-')
            return f"{type_short}-{ip_suffix}"
        
        # Last resort: just use IP suffix
        return f"Unknown-{ip_suffix}"
    
    def _scan_ports(self, ip, timeout=0.5):
        """Scan common ports on device (accurate scan with proper error checking)"""
        # Reduced port list for faster scanning (removed VPN ports as they're not useful for local detection)
        common_ports = {
            22: 'SSH',
            80: 'HTTP',
            443: 'HTTPS',
            445: 'SMB',
            554: 'RTSP',
            3389: 'RDP',
            5900: 'VNC',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt'
        }
        
        open_ports = []
        
        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                # Port is open only if connect_ex returns 0
                if result == 0:
                    open_ports.append({'port': port, 'service': service})
                    
            except Exception:
                # Silently skip ports that can't be scanned
                pass
        
        return open_ports
    
    def _get_hostname(self, ip):
        """Try to get device hostname using multiple methods"""
        hostname = 'Unknown'
        
        # Method 1: Try reverse DNS lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname and hostname != ip:
                return hostname
        except:
            pass
        
        # Method 2: Try NetBIOS name resolution (Windows devices)
        try:
            import subprocess
            result = subprocess.check_output(['nmblookup', '-A', ip], timeout=2, stderr=subprocess.DEVNULL).decode()
            for line in result.split('\n'):
                if '<00>' in line and 'GROUP' not in line:
                    # Extract NetBIOS name
                    name = line.split()[0].strip()
                    if name and name != ip:
                        return name
        except:
            pass
        
        # Method 3: Try mDNS/Avahi (Apple devices and some Linux)
        try:
            import subprocess
            result = subprocess.check_output(['avahi-resolve', '-a', ip], timeout=2, stderr=subprocess.DEVNULL).decode()
            if result:
                parts = result.strip().split()
                if len(parts) >= 2:
                    name = parts[1].replace('.local', '')
                    if name and name != ip:
                        return name
        except:
            pass
        
        # Method 4: Check /etc/hosts
        try:
            with open('/etc/hosts', 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        parts = line.split()
                        if len(parts) >= 2 and parts[0] == ip:
                            return parts[1]
        except:
            pass
        
        # Method 5: Try to get hostname from DHCP leases (if running as router)
        try:
            # Common DHCP lease file locations
            lease_files = [
                '/var/lib/dhcp/dhcpd.leases',
                '/var/lib/dhcpd/dhcpd.leases',
                '/var/db/dhcpd.leases'
            ]
            for lease_file in lease_files:
                try:
                    with open(lease_file, 'r') as f:
                        content = f.read()
                        # Look for this IP in leases
                        if ip in content:
                            lines = content.split('\n')
                            for i, line in enumerate(lines):
                                if f'lease {ip}' in line:
                                    # Look for hostname in next few lines
                                    for j in range(i, min(i+10, len(lines))):
                                        if 'client-hostname' in lines[j]:
                                            name = lines[j].split('"')[1]
                                            if name:
                                                return name
                except:
                    continue
        except:
            pass
        
        return hostname


def get_connected_devices():
    """Get list of all connected devices"""
    with _devices_lock:
        return {
            'devices': list(_connected_devices.values()),
            'total_count': len(_connected_devices),
            'last_scan': _last_scan_time,
            'device_summary': _get_device_summary()
        }


def _get_device_summary():
    """Get summary of device types"""
    summary = defaultdict(int)
    for device in _connected_devices.values():
        device_type = device['type']
        summary[device_type] += 1
    return dict(summary)


def get_device_history():
    """Get devices seen in last 7 days (excluding currently connected)"""
    with _devices_lock:
        # Clean old history
        _cleanup_device_history()
        
        # Get devices that are in history but NOT currently connected
        current_macs = set(_connected_devices.keys())
        historical_devices = []
        
        for mac, device in _device_history.items():
            if mac not in current_macs:
                historical_devices.append(device)
        
        # Sort by last seen (most recent first)
        historical_devices.sort(key=lambda d: d['last_seen'], reverse=True)
        
        return {
            'devices': historical_devices,
            'total_count': len(historical_devices)
        }


def _cleanup_device_history():
    """Remove devices older than HISTORY_RETENTION_DAYS"""
    cutoff_time = (datetime.now() - timedelta(days=HISTORY_RETENTION_DAYS)).isoformat()
    to_remove = []
    
    for mac, device in _device_history.items():
        if device['last_seen'] < cutoff_time:
            to_remove.append(mac)
    
    for mac in to_remove:
        del _device_history[mac]


def clear_device_history():
    """Clear all device history records"""
    global _device_history
    with _devices_lock:
        _device_history = {}
        _save_state()
        print(f"[DEVICE SCANNER] Device history cleared")
    return True


def block_device(mac, ip):
    """Block a device by MAC/IP address using ARP spoofing"""
    if not BLOCKER_AVAILABLE:
        print(f"[DeviceScanner] ERROR: Blocker not available")
        return False
    
    print(f"[DeviceScanner] Blocking device: {mac} ({ip}) via ARP spoofing")
    return _block_device_real(mac, ip)


def unblock_device(mac, ip):
    """Unblock a device by MAC/IP address"""
    if not BLOCKER_AVAILABLE:
        print(f"[DeviceScanner] ERROR: Blocker not available")
        return False
    
    print(f"[DeviceScanner] Unblocking device: {mac} ({ip})")
    return _unblock_device_real(mac, ip)


def is_device_blocked(mac):
    """Check if a device is blocked"""
    if not BLOCKER_AVAILABLE:
        return False
    return _is_blocked_real(mac)


def trigger_manual_scan():
    """Manually trigger a device scan and return results"""
    global scanner
    
    if not SCAPY_AVAILABLE:
        return {
            'devices': [],
            'total_count': 0,
            'last_scan': None,
            'device_summary': {},
            'error': 'scapy not available'
        }
    
    print("[DEVICE SCANNER] Manual scan triggered")
    scanner._scan_network()
    
    # Return current device data
    return get_connected_devices()


# Global scanner instance
scanner = DeviceScanner()
