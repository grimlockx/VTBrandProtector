# VTBrandProtector
This Python script enables bulk VirusTotal queries for proactive brand protection. It helps identify potential phishing attacks impersonating your brand, uncovers typosquatted domains, and detects unauthorized use of your company's or client's branding elements such as favicons.

## Installation

```bash
git clone https://github.com/grimlockx/VTBrandProtector/
cd VTBrandProtector
echo "VT_API_KEY=YOUR_VT_API_KEY" > .env
pip install vt-py
```

Make sure to modify the `query_data.json` according to your monitoring needs. If you want to monitor multiple companies or customers, simply duplicate the template within the JSON file.

## Usage
```bash
python VTBRandProtector.py path_to_json_file.json
```

## To Do
[] Implement postfix connection to send alerts via email.
[] Implement a database to track alerts and ensure alerts are not duplicated.
