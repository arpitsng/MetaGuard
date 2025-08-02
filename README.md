
# 🛡️ MetaGuard

**MetaGuard** is a web-based file forensics and threat analysis tool that performs deep inspection of uploaded files. It offers metadata extraction, steganography detection, macro checking, VirusTotal scan, and privacy-focused file cleaning — all in one place.

🌐 **Live Demo:** [https://metaguard-6.onrender.com](https://metaguard-6.onrender.com)

---

## 📌 Features

- 🔍 **Metadata Extraction** (Images, PDFs)
- ⚠️ **Risk Assessment** based on metadata content
- 🧬 **Steganography Detection** (LSB analysis)
- 📜 **Macro Detection** in Office documents
- 🦠 **VirusTotal Integration** for malware reports
- 🔗 **Embedded URL Detection** in PDFs
- 🧹 **Metadata Cleaning**
- 🔧 **Steganography Destruction**

---

## 🛠️ Tech Stack

- **Backend:** Python, FastAPI
- **Frontend:** HTML, CSS (custom design)
- **File Analysis:** Pillow, ExifRead, PyPDF2, python-magic
- **Threat Intelligence:** VirusTotal Public API

---

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/arpitsng/MetaGuard.git
cd MetaGuard
```

### 2. Create a virtual environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install dependencies

> 🐧 On **Linux**, ensure you have `libmagic` installed:  
> `sudo apt install libmagic1`

```bash
pip install -r requirements.txt
```

📌 Note:
- Linux uses: `python-magic==0.4.27`
- Windows users must install: `python-magic-bin==0.4.14`

### 4. Set up environment variables

Create a `.env` file in the root directory:

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
```

You can obtain a free API key from: https://virustotal.com

---

## ⚡ Running Locally

### Start the server:

```bash
python api.py
```

Then visit: [http://localhost:8000](http://localhost:8000)

---

## 📂 Project Structure

```
MetaGuard/
│
├── main.py              # Core engine for analysis & cleaning
├── api.py               # FastAPI server and endpoints
├── index.html           # UI served directly from backend
├── requirements.txt     # Python dependencies
└── .env                 # API keys and secrets (you create this)
```

---

## 🧪 Supported File Types

- Images: `.jpg`, `.jpeg`, `.png`, `.tiff`
- Documents: `.pdf`, `.docx`, `.pptx`, `.xlsx`, `.docm`, `.pptm`, `.xlsm`
- Executables (basic type detection and hash checking)

---

## ✅ Usage Flow

1. Upload a file via the UI
2. The backend performs:
   - File type validation
   - Metadata parsing
   - Threat and privacy analysis
   - VirusTotal scanning
3. Interactive results are displayed with:
   - Visual sections
   - File cleaning options (metadata/steganography)

---

## 🔒 Privacy and Security

- Files are processed in memory or temporary storage.
- Nothing is stored permanently.
- Cleaning options strip metadata or destroy embedded steganography.

---

## 📜 License

This project is open-source and available under the **MIT License**.

---

## 👨‍💻 Author

**Arpit Singh**  
[GitHub Profile](https://github.com/arpitsng)
