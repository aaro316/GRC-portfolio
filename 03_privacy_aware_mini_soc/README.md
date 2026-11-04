# Privacy-Aware Mini SOC
### Threat Detection and Incident Response Using Python

## 1. Project Overview

The Privacy-Aware Mini SOC is a Python-based Security Operations Centre (SOC) project designed to detect suspicious authentication activity using rule-based detection.

The project simulates a basic SOC workflow by processing synthetic authentication logs, identifying suspicious login patterns, generating security alerts, and providing an interactive dashboard for monitoring and investigation.

It also incorporates privacy-aware logging practices, data minimisation, and basic automated testing.

## 2. Objectives

- Generate and analyse synthetic authentication events.
- Detect brute-force login attempts.
- Identify successful logins following repeated authentication failures.
- Store and manage security alerts using SQLite.
- Provide an interactive dashboard for alert monitoring and investigation.
- Demonstrate basic privacy-aware logging practices.
- Test detection logic and privacy functions.

## 3. Technologies Used

| Technology | Purpose |
|---|---|
| Python | Event processing and detection logic |
| SQLite | Alert storage and management |
| Streamlit | Interactive SOC dashboard |
| Pandas | Data handling and visualisation |
| JSONL | Synthetic authentication log storage |
| Unittest | Automated testing |

## 4. System Architecture

1. **Log Generation:** `generate_sample.py` creates synthetic authentication events.
2. **Event Processing:** `detector.py` reads and processes authentication logs.
3. **Threat Detection:** Rule-based detection identifies suspicious login patterns.
4. **Alert Storage:** `database.py` stores alerts in an SQLite database.
5. **Dashboard:** `app.py` displays metrics, alerts, filters, and investigation status.
6. **Testing:** Automated tests validate detection logic and privacy functions.

## 5. Detection Rules

### Rule 1: Repeated Failed Logins

- Detects at least five failed login attempts from the same source IP address within a rolling five-minute window.
- Generates a High-severity alert.

### Rule 2: Successful Login After Repeated Failures

- Detects a successful login following at least three failed attempts for the same username and source IP within ten minutes.
- Generates a High-severity alert.

## 6. Privacy-Aware Features

- Uses synthetic authentication data instead of real user logs.
- Uses documentation-only IP address ranges in the sample dataset.
- Masks IPv4 and IPv6 addresses in console alert output.
- Masks usernames in console alert output.
- Documents data minimisation, retention considerations, and project limitations.

**Privacy limitation:** Masking currently applies to console output only. Original usernames and IP addresses remain in the local SQLite database and dashboard to support investigation. Dashboard authentication and role-based access control have not been implemented.

## 7. Project Structure

```text
03_privacy_aware_mini_soc/
│
├── app.py
├── database.py
├── detector.py
├── generate_sample.py
├── requirements.txt
├── README.md
├── privacy_notes.md
├── test_plan.md
├── test_database.py
│
├── data/
│   └── events.jsonl
│
├── tests/
│   ├── test_detector.py
│   └── test_privacy.py
│
├── reports/
│   └── sample_incident_report.md
│
└── screenshots/
    └── dashboard.png
```

## 8. Installation and Execution

### Step 1: Clone the repository

```bash
git clone https://github.com/aaro316/GRC-portfolio.git
cd GRC-portfolio/03_privacy_aware_mini_soc
```

### Step 2: Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Generate synthetic events

```bash
python3 generate_sample.py
```

### Step 5: Run threat detection

```bash
python3 detector.py
```

### Step 6: Launch the SOC dashboard

```bash
python3 -m streamlit run app.py
```

Open the local URL displayed in the terminal to access the dashboard.

## 9. Testing

Automated tests are implemented using Python's `unittest` framework.

Run the test suite using:

```bash
python3 -m unittest discover -s tests -v
```

The tests cover:

- Normal successful login activity.
- Repeated failed login attempts.
- Successful login following repeated failures.
- Failed attempts outside the detection time window.
- Failed attempts originating from different IP addresses.
- IPv4 and IPv6 masking.
- Username masking and invalid input handling.

## 10. Limitations and Future Enhancements

- Integrate real-time log ingestion from Linux systems.
- Add authentication and role-based access control to the dashboard.
- Implement automated log retention and deletion.
- Integrate with SIEM platforms such as Wazuh.
- Introduce additional detection rules and severity levels.
- Improve alert prioritisation and incident response workflows.

## 11. Disclaimer

This project is an educational cybersecurity prototype developed using synthetic authentication data. It demonstrates basic Security Operations Centre workflows and privacy-aware logging concepts. It does not claim compliance with any cybersecurity or privacy standard or regulation.
