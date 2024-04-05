<div id="top" align="center">

<!-- Shields Header -->
[![Contributors][contributors-shield]](https://github.com/franckferman/LastLog-Audit/graphs/contributors)
[![Forks][forks-shield]](https://github.com/franckferman/LastLog-Audit/network/members)
[![Stargazers][stars-shield]](https://github.com/franckferman/LastLog-Audit/stargazers)
[![Issues][issues-shield]](https://github.com/franckferman/LastLog-Audit/issues)
[![License][license-shield]](https://github.com/franckferman/LastLog-Audit/blob/stable/LICENSE)

<!-- Logo -->
<a href="https://github.com/franckferman/LastLog-Audit">
  <img src="https://raw.githubusercontent.com/franckferman/LastLog-Audit/stable/docs/github/graphical_resources/Logo-Without_background-LastLog-Audit.png" alt="LastLog-Audit Logo" width="auto" height="auto">
</a>

<!-- Title & Tagline -->
<h3 align="center">📝 LastLog Audit: Security Login Activity Analyzer.</h3>
<p align="center">
    <em>Analyzing system login activities for security audits and compliance.</em>
    <br>
     LastLog Audit offers a comprehensive and customizable solution for analyzing login activities on Linux/Unix systems. Designed for system administrators and security professionals, it facilitates security audits, compliance checks, and forensic investigations with ease.
</p>

<!-- Links & Demo -->
<p align="center">
    <a href="https://github.com/franckferman/LastLog-Audit/blob/stable/README.md" class="button-style"><strong>📘 Explore the full documentation</strong></a>
    ·
    <a href="https://github.com/franckferman/LastLog-Audit/issues">🐞 Report Bug</a>
    ·
    <a href="https://github.com/franckferman/LastLog-Audit/issues">🛠️ Request Feature</a>
</p>

</div>

## 📜 Table of Contents

<details open>
  <summary><strong>Click to collapse/expand</strong></summary>
  <ol>
    <li><a href="#-about">📖 About</a></li>
    <li><a href="#-installation">🛠️ Installation</a></li>
    <li><a href="#-usage">🎮 Usage</a></li>
    <li><a href="#-troubleshooting">❗ Troubleshooting</a></li>
    <li><a href="#-contributing">🤝 Contributing</a></li>
    <li><a href="#-star-evolution">🌠 Star Evolution</a></li>
    <li><a href="#-license">📜 License</a></li>
    <li><a href="#-contact">📞 Contact</a></li>
  </ol>
</details>

## 📖 About

**LastLog Audit: Security Login Activity Analyzer** _Enhance your security audits and compliance checks._

`LastLog-Audit` offers a comprehensive solution for analyzing system login activities, designed to assist in security audits, compliance checks, and forensic investigations on Linux/Unix systems. This tool parses `/var/log/lastlog` to provide detailed and customizable reports on user login activities, making it an indispensable asset for system administrators and security professionals.

<p align="center">
  <img src="https://raw.githubusercontent.com/franckferman/LastLog-Audit/stable/docs/github/graphical_resources/Screenshot-LastLog-Audit_Demo.png" alt="LastLog-Audit Demo Screenshot" width="auto" height="auto">
</p>

Discover the potential of `LastLog-Audit` in streamlining your security processes. Whether it's for enhancing security protocols, ensuring compliance, or conducting detailed forensic analyses, `LastLog-Audit` brings robustness and ease to the management of login activity data. Dive into a new level of audit efficiency and control with `LastLog-Audit`. Begin your journey towards more secure and compliant systems today.

<p align="right">(<a href="#top">🔼 Back to top</a>)</p>

## 🚀 Installation

Setting up `LastLog-Audit` is streamlined for ease of use. Please follow the guidelines below to ensure you meet the necessary prerequisites before installation.

### Prerequisites

`LastLog-Audit` is developed for Linux/Unix environments, focusing on delivering a robust login activity analysis tool. Here's what you need to know about its compatibility:

Ensure Python 3.11.2 or newer is installed on your system. You can check your current Python version by running `python3 --version` in your terminal. If you need to upgrade or install Python, use your distribution's package manager or visit the official [Python website](https://www.python.org/downloads/) for more detailed instructions.

> ⚠️ **Note**: `LastLog-Audit` has been rigorously tested on **Ubuntu 23.10 x64**. This testing was conducted using **Python 3.11.2**. While `LastLog-Audit` is expected to function on other Unix-like systems and versions of Python above 3.6, Ubuntu 23.10 x64 with Python 3.11.2 is the recommended setup for the most reliable experience.

### Getting LastLog-Audit

To get started with LastLog Audit, you can choose from downloading it directly, cloning the repo, or using a command to pull the latest version. Here's how:

Option 1: **Using wget or curl**
For a quick setup, you can download the main script using wget or curl:
```bash
# Using wget
wget https://raw.githubusercontent.com/franckferman/LastLog-Audit/stable/LastLog-Audit.py

# Or using curl
curl -O https://raw.githubusercontent.com/franckferman/LastLog-Audit/stable/LastLog-Audit.py
```

Option 2: **Clone with Git**
First, ensure you have Git installed on your system. Open your favorite terminal and run the following command to clone the repository:
```bash
git clone https://github.com/franckferman/LastLog-Audit.git
```

This method clones the entire project to your local machine.

Option 3: **Direct Download** from GitHub
If you prefer not using Git, you can download the project directly:

Visit the project's page at `https://github.com/franckferman/LastLog-Audit`.
Click on the `<> Code` button, then select `Download ZIP`.
After downloading, extract the ZIP file to your preferred location.

Whichever method you choose, ensure Python 3 is installed on your system to run LastLog Audit successfully.

<p align="right">(<a href="#top">🔼 Back to top</a>)</p>

## 🎮 Usage

Using `LastLog Audit` is straightforward, enabling you to analyze system login activities efficiently. Here's how to get started:

### **Getting started**

To run `LastLog Audit`, execute the following command in your terminal, adjusting the script name as necessary:
```bash
python3 LastLog-Audit.py
```

### Usage Options

`LastLog Audit` comes with a variety of options to customize its output and functionality. Here’s a quick overview:

- --file FILE: Specifies the path to the lastlog file. The default is /var/log/lastlog.
- --display {table,line}: Chooses between tabular (table) and line-by-line (line) output formats. The default is table.
- --include-username: Includes usernames in the output. Note: This is accurate only when run on the target system due to UID mapping.
- --export EXPORT: Specifies the path for exporting the data. If left unspecified, the output is displayed in the console.
- --export-format {txt,csv}: Determines the format for exported data (txt or csv). This option requires --export to be set.

### Examples

Here are a few examples to illustrate common `LastLog Audit` usage scenarios:

Analyze and display last login activities in a table format (default behavior):
```bash
python3 LastLog-Audit.py
```

Export last login activities to a CSV file:
```bash
python3 LastLog-Audit.py --export ~/output.csv --export-format csv
```

Include usernames and display output in line-by-line format:
```bash
python3 LastLog-Audit.py --include-username --display line
```

For more details on all available options, run `python3 LastLog-Audit.py -h`.

<p align="right">(<a href="#top">🔼 Back to top</a>)</p>

## 🔧 Troubleshooting

Encountering issues? Don't worry. If you come across any problems or have questions, please don't hesitate to submit a ticket for assistance: [Submit an issue on GitHub](https://github.com/franckferman/LastLog-Audit/issues)

<p align="right">(<a href="#top">🔼 Back to top</a>)</p>

## 🤝 Contributing

We truly appreciate and welcome community involvement. Your contributions, feedback, and suggestions play a crucial role in improving the project for everyone. If you're interested in contributing or have ideas for enhancements, please feel free to open an issue or submit a pull request on our GitHub repository. Every contribution, no matter how big or small, is highly valued and greatly appreciated!

<p align="right">(<a href="#top">🔼 Back to top</a>)</p>

## 🌠 Star Evolution

Explore the star history of this project and see how it has evolved over time:

<a href="https://star-history.com/#franckferman/LastLog-Audit&Timeline">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=franckferman/LastLog-Audit&type=Timeline&theme=dark" />
    <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=franckferman/LastLog-Audit&type=Timeline" />
  </picture>
</a>

Your support is greatly appreciated. We're grateful for every star! Your backing fuels our passion. ✨

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
[forks-shield]: https://img.shields.io/github/forks/franckferman/LastLog-Audit.svg?style=for-the-badge
[forks-url]: https://github.com/franckferman/LastLog-Audit/network/members
[stars-shield]: https://img.shields.io/github/stars/franckferman/LastLog-Audit.svg?style=for-the-badge
[stars-url]: https://github.com/franckferman/LastLog-Audit/stargazers
[issues-shield]: https://img.shields.io/github/issues/franckferman/LastLog-Audit.svg?style=for-the-badge
[issues-url]: https://github.com/franckferman/LastLog-Audit/issues
[license-shield]: https://img.shields.io/github/license/franckferman/LastLog-Audit.svg?style=for-the-badge
[license-url]: https://github.com/franckferman/LastLog-Audit/blob/stable/LICENSE
[protonmail-shield]: https://img.shields.io/badge/ProtonMail-8B89CC?style=for-the-badge&logo=protonmail&logoColor=blueviolet
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=blue
[twitter-shield]: https://img.shields.io/badge/-Twitter-black.svg?style=for-the-badge&logo=twitter&colorB=blue
