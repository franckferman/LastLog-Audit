<div id="top" align="center">

<!-- Shields Header -->
[![Contributors][contributors-shield]](https://github.com/franckferman/LastLog-Audit/graphs/contributors)
[![Stargazers][stars-shield]](https://github.com/franckferman/LastLog-Audit/stargazers)
[![License][license-shield]](https://github.com/franckferman/LastLog-Audit/blob/stable/LICENSE)

<!-- Logo -->
<a href="https://github.com/franckferman/LastLog-Audit">
  <img src="https://raw.githubusercontent.com/franckferman/LastLog-Audit/refs/heads/stable/docs/github/graphical_resources/Logo-without_background-LastLog-Audit.png" alt="LastLog-Audit Logo" width="auto" height="auto">
</a>

<!-- Title & Tagline -->
<h3 align="center">🧭 LastLog-Audit</h3>
<p align="center">
    <em>Analyzing system login activities.</em>
    <br>
    A Python tool to analyze and export login activity from /var/log/lastlog for security.
</p>

</div>

## 📜 Table of Contents

<details open>
  <summary><strong>Click to collapse/expand</strong></summary>
  <ol>
    <li><a href="#-about">📖 About</a></li>
    <li><a href="#-installation">🛠️ Installation</a></li>
    <li><a href="#-usage">🎮 Usage</a></li>
    <li><a href="#-contributing">🤝 Contributing</a></li>
    <li><a href="#-license">📜 License</a></li>
    <li><a href="#-contact">📞 Contact</a></li>
  </ol>
</details>

## 📖 About

**LastLog-Audit** is a lightweight Python tool designed to **parse and analyze system login activity** stored in `/var/log/lastlog`.

Originally built for personal use and professional system audits, this tool offers **customizable output** (table/line) and **export options (TXT/CSV)** for easy reporting, tracking, and compliance.

> ⚙️ **Note:** LastLog-Audit is a simple, focused tool — perfect for quick audits and reviews.

### ⚙️ **Features of _LastLog-Audit_**

- ✅ Parse `/var/log/lastlog` and extract login records (terminal, hostname, last login date).
- ✅ Optionally **include usernames** mapped via system UID.
- ✅ **Multiple output modes**: clean **table view** or **line output** (easy for grep/awk parsing).
- ✅ **Export to TXT or CSV** formats for archiving and sharing reports.

<p align="right">(<a href="#top">🔼 Back to top</a>)</p>

## 🚀 Installation

Before getting started, make sure you meet the following prerequisites.

### Prérequis

1. **Python 3**: Ensure Python 3 is installed on your system.

2. **Dependencies**: No external libraries required.

LastLog-Audit relies **only on Python's standard library** — ready to use out-of-the-box on any modern Linux system (Python 3.7+).

> ⚙️ Optional: For Python 3.6 support, you may install the backport of `dataclasses` via `pip install dataclasses`.

> ⚠️ Note: LastLog-Audit has been tested on Python 3.11.10 under Linux. While it might work on other versions or operating systems, compatibility is officially guaranteed only for this specific setup.

### Installation Methods

1. **Clone the repository via Git**:
```bash
git clone https://github.com/franckferman/LastLog-Audit.git
```

2. **Direct download of the script (_without Git_)**:
If you only need the script without cloning the entire repository:
```bash
curl -O https://raw.githubusercontent.com/franckferman/LastLog-Audit/stable/src/LastLog-Audit.py
```

<p align="right">(<a href="#top">🔼 Back to top</a>)</p>

## 🎮 Usage

Make sure to adjust the commands based on your setup.

### **Basic usage**

To display the full help menu and explore available options:

```bash
python3 LastLog-Audit.py --help
```

### 📝 **Example Commands**

| Task | Command |
| --- | --- |
| Parse and display lastlog in a table | `python3 LastLogAudit.py` |
| Show logins in a simple line format | `python3 LastLogAudit.py --display line` |
| Include usernames (if available) | `python3 LastLogAudit.py --include-username` |
| Export to CSV | `python3 LastLogAudit.py --export output.csv --export-format csv` |
| Export to TXT (table format) | `python3 LastLogAudit.py --export output.txt` |
| Parse a custom lastlog file | `python3 LastLogAudit.py --file /path/to/custom_lastlog` |

<p align="right">(<a href="#top">🔼 Back to top</a>)</p>

## 🤝 Contributing

We truly appreciate and welcome community involvement. Your contributions, feedback, and suggestions play a crucial role in improving the project for everyone. If you're interested in contributing or have ideas for enhancements, please feel free to open an issue or submit a pull request on our GitHub repository. Every contribution, no matter how big or small, is highly valued and greatly appreciated!

<p align="right">(<a href="#top">🔼 Back to top</a>)</p>

## 📚 License

This project is licensed under the GNU Affero General Public License, Version 3.0. For more details, please refer to the LICENSE file in the repository: [Read the license on GitHub](https://github.com/franckferman/LastLog-Audit/blob/stable/LICENSE)

<p align="right">(<a href="#top">🔼 Back to top</a>)</p>

## 📞 Contact

[![ProtonMail][protonmail-shield]](mailto:contact@franckferman.fr)
[![LinkedIn][linkedin-shield]](https://www.linkedin.com/in/franckferman)
[![Twitter][twitter-shield]](https://www.twitter.com/franckferman)

<p align="right">(<a href="#top">🔼 Back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/franckferman/LastLog-Audit.svg?style=for-the-badge
[contributors-url]: https://github.com/franckferman/LastLog-Audit/graphs/contributors
[stars-shield]: https://img.shields.io/github/stars/franckferman/LastLog-Audit.svg?style=for-the-badge
[stars-url]: https://github.com/franckferman/LastLog-Audit/stargazers
[license-shield]: https://img.shields.io/github/license/franckferman/LastLog-Audit.svg?style=for-the-badge
[license-url]: https://github.com/franckferman/LastLog-Audit/blob/stable/LICENSE
[protonmail-shield]: https://img.shields.io/badge/ProtonMail-8B89CC?style=for-the-badge&logo=protonmail&logoColor=blueviolet
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=blue
[twitter-shield]: https://img.shields.io/badge/-Twitter-black.svg?style=for-the-badge&logo=twitter&colorB=blue

