1. Project Scope &amp; Realized Implementation Architecture
The Malicious Threat Scanner &amp; Response System is an AI-assisted security solution
developed specifically for the OSF Hackathon context. The codebase establishes a functional
client-server model focused on endpoint activity auditing, background event observation, and
synchronous user warning systems through a web interface. By shifting away from hypothetical
enterprise EDR assumptions, this technical specification documents the code&#39;s concrete
implementation scope, focusing on verified Python modules and React component interactions.
Code Audit Notice: This document outlines the verified capabilities within the submitted code layers,
using an on-disk SQLite persistence engine (sentinelx.db) and focused monitoring namespaces.

2. Core Technical Objectives
 Endpoint Monitoring: Execute foreground and background telemetry tracking of active
runtime elements using targeted operating system interfaces.
 Behavioral Profiling: Evaluate changing states in specific directories and runtime execution
fields via rule-based metrics and risk markers.
 Threat Intelligence Brokerage: Enrich local detection data by querying external APIs when
specific file state changes or warnings are logged.
 Mitigation Execution: Provide immediate mitigation workflows, such as killing target
processes or isolating files, directly from a centralized administrator dashboard.
3. System Architecture &amp; Internal Components
The implementation follows a clean decoupled structure consisting of a React-driven user
interface and an asynchronous FastAPI application wrapper.
3.1 Core Architecture Flow Mapping
• React Frontend Interface (Dashboard, Real-time Charts, Process Lists)
│ (Exchanges data over HTTP REST using JSON Data Formats via Axios client)
• FastAPI Application Routing Layer
├── Authentication Broker (JWT Tokens &amp; Cryptographic Password Checking)
├── Monitoring Controller (Coordinates individual monitoring threads)
│ ├── Process Tracker (psutil engine context loops)
│ ├── File System Monitor (watchdog monitoring loops over target paths)
│ └── USB Device Listener (Monitors storage attachment signals)

├── Threat Analysis Engine (Evaluates heuristic threat weights)
├── External Integrations (VirusTotal API reputation checks)
└── Persistence Layer (SQLAlchemy ORM mapping to sentinelx.db SQLite file)
4. Subsystem Module Audits
4.1 Authentication Subsystem
Located within the app/auth/ directory path, this module handles identity validation and API
route protection. Key files include:
 auth/routes.py: Defines user authentication endpoints and session validation rules.
 auth/security.py: Implements security protocols, cryptographic signature utilities, and token
creation routines.
 auth/dependencies.py: Handles parameter checks, extract headers, and checks role-
based access privileges.
4.2 System Monitoring Controller
The monitoring components run as background threads managed by a central manager:
 Process Tracker: Leverages psutil to gather data on running processes, CPU loads, and
active memory allocation states.
 File Monitor: Uses the watchdog framework to track a target watch folder, immediately
catching file creation, mutation, and removal actions.
 USB Monitoring Module: Listens for removable hardware storage attachments, sending
data back to the primary alert stream.
 Monitoring Manager: Acts as an orchestrator that boots monitoring loops, tracks execution
status, and ensures cross-module synchronization.
4.3 Detection &amp; External Intelligence Packages
The app/detection/threat_detector.py file runs heuristic checks to generate threat scores based
on process parameters and file attributes. Once labeled suspicious, the file details are passed to
the intelligence subsystem:
intelligence/
├── virustotal.py # Manages outbound communication with the VirusTotal public
API
└── signatures.py # Evaluates static file patterns and localized rule-sets

4.4 Incident Mitigation &amp; Response Logic
The app/response/ directory contains code designed to mitigate identified threats based on
configuration toggles:

 Process Killer: Executes process termination tasks via targeted system calls using the
target PID.
 File Quarantine: Moves suspected malicious files out of active folders into an isolated
cryptographic holding directory.
 Alert Generation: Writes incidents directly to persistent storage to display them in the live
UI feed.
5. Technical Stack &amp; File Tree Blueprint
Layer Component Tech Implementation Target Scope
Frontend UI React, Vite, Tailwind CSS Web UI dashboards, system stats,

charts

API Layer FastAPI, Uvicorn Server Asynchronous endpoints, request

routing

OS Telemetry psutil, watchdog framework Process tracking, file change

events

Storage Layer SQLite (sentinelx.db),
SQLAlchemy

Relational database logs, alert
tables

External Services VirusTotal Public API Core Remote hash validation and

lookups

5.1 Project Layout
backend/app/
├── api/ # API router endpoints
├── auth/ # Authentication &amp; security handlers
├── core/ # Configuration options and core logic
├── database/ # Models &amp; database session scripts
├── detection/ # Threat scoring and analysis code
├── intelligence/ # VirusTotal client integrations
├── monitoring/ # psutil and watchdog threads
├── response/ # Threat mitigation tools
└── main.py # Primary system launch file

6. Internal API Interface Definitions

Method URI Path Route Backend Component Action

POST /login Validates user credentials and
issues a JWT token.

GET /system/status Returns host hardware telemetry

(CPU, RAM).

GET /processes Lists current running processes

and metadata.

GET /alerts Queries sentinelx.db for generated

alerts.

POST /response/kill-process Terminates a running target

process via PID.

POST /response/quarantine Isolates a suspicious file to a

secure directory.

POST /simulation Triggers simulated threat events

for system testing.

7. Runtime Processes &amp; Workflows
7.1 Monitoring &amp; Alert Workflow Lifecycle
1. System Starts -&gt; Initialize Configuration Models
2. Launch Monitoring Manager -&gt; Start Background Isolation Threads
3. Process Tracker (psutil) &amp; File Monitor (watchdog) begin data ingestion loops
4. Intercept Events -&gt; Process passes payload to Threat Detector engine
5. Run Heuristic Review -&gt; Cross-checks file details using the VirusTotal API client
6. Log Incidents -&gt; Appends threat entries to sentinelx.db &amp; sends data to dashboard
7. UI Auto-Refresh -&gt; Renders alert components and updates status graphs
7.2 Local Test Cases &amp; Simulated Payloads
The watch_folder/ path contains test targets designed to verify the watchdog monitor and
detection scoring logic:

 hello.txt / test123.txt: Validates typical, clean text-file monitoring pipelines.
 invoice.pdf.exe: Triggers double-extension scoring rules within the detector module.
 encrypted.locked: Simulates a simulated ransomware artifact to test alert triggering.
8. Frontend UI Components
The frontend application dashboard uses structured React layout components to present
endpoint data clearly:
 Alerts Panel: Renders active alerts stored in the SQLite database.
 Process &amp; Network Tables: Displays live system performance data and active processes
via psutil.
 Threat Chart: Uses Chart.js to visualize incident trends over time.
 Settings Modal: Allows administrators to change active parameters and modify monitoring
behavior.
9. System Scope Limitations &amp; Future Roadmap
This implementation provides a solid framework for endpoint monitoring within a hackathon
project scope. To scale this into a production-ready Endpoint Detection and Response (EDR)
solution, the following enhancements are planned:
 Database Scaling: Migrate from simple on-disk SQLite storage to enterprise database
clusters with connection pooling.
 Heuristic Enhancements: Replace basic signature and file rule sets with local deep
learning models for advanced threat detection.
 Deep System Monitoring: Add kernel-level drivers to capture low-level operating system
events that standard user-space tools miss.
