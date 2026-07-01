# 🛡️ PhishGuard System

An end-to-end, full-stack cybersecurity application that leverages Machine Learning (ML) to perform real-time URL structure dissection and phishing classification. 

The system features a decoupled cloud architecture: a sleek interactive frontend dashboard connected via a secure API pipeline to a silent, high-performance ML prediction core engine.

---

## 🔗 Live Application Links

* **🖥️ User Dashboard (Frontend):** [phishguard-dashboard-smjr.onrender.com](https://phishguard-dashboard-smjr.onrender.com)
* **⚙️ Core Prediction Engine (Backend API):** [phishguard-backend-api.onrender.com](https://phishguard-backend-api.onrender.com)
* **📑 Interactive API Blueprint:** [phishguard-backend-api.onrender.com/docs](https://phishguard-backend-api.onrender.com/docs)

---


└───────────────┘

1. **The Frontend Dashboard (`Streamlit`):** A responsive, client-facing graphical interface built to securely ingest URLs, manage layout components, display real-time safety matrices, and visualize JSON deep-inspection metrics.
2. **The Backend Engine (`FastAPI`):** A robust RESTful API that handles input sanitization, structural metadata extraction (SSL validation state, domain parsing), pipeline execution, and model response formulation.

---

## 📊 Core Features

* **Real-Time Vector Dissection:** Extracts underlying deep-inspection metrics dynamically, checking for domain registration age, SSL issuer records, visual character spoofing, and hidden form inputs.
* **Machine Learning Probability:** Utilizes pre-trained classification models serialized via `joblib` to calculate a localized threat score mapping from 0 to 100.
* **Robust Fallback Mechanisms:** Built-in calculation catch blocks to prevent operational engine errors (`500 Internal Server Errors`) if network timeouts occur during metadata lookup.

---

## 🛠️ Technology Stack

* **Frontend UI:** Streamlit (Python Core Framework)
* **Backend Framework:** FastAPI, Uvicorn
* **Machine Learning Ecosystem:** Scikit-Learn, Joblib
* **Data Validation:** Pydantic v2
* **Hosting & Infrastructure:** Render Cloud Platform (Decoupled Web Services)

---

## 🚀 Local Installation & Setup

If you want to pull down this code and spin up the backend and frontend locally on your machine, follow these steps:

### 1. Clone the Workspace
```bash
git clone [https://github.com/SAKSHI1243/phishguard-system.git](https://github.com/SAKSHI1243/phishguard-system.git)
cd phishguard-system
2. Install Dependencies
Ensure your local system has Python 3 installed, then load the required packages:

Bash
pip install -r requirements.txt
3. Start the Backend API Engine
Run the Uvicorn server to host the local endpoint on port 8000:

Bash
uvicorn main:app --reload
Your interactive documentation will now be available at http://127.0.0.1:8000/docs.

4. Wire and Boot the Frontend Dashboard
Ensure the BACKEND_URL pointing key inside your local app.py matches your local server instance, then boot the dashboard interface:

Bash
streamlit run app.py
