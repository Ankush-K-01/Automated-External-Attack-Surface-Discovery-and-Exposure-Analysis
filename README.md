# Automated External Attack Surface Discovery and Exposure Analysis

**Status:** 🚧 In Progress

## Overview

This project presents an automated workflow for **External Attack Surface Discovery (EASM)** and **security exposure analysis**. The system identifies publicly observable assets associated with a defined target domain, consolidates the discovered information, analyzes security exposures, enriches findings with threat intelligence, validates findings using AI, and prioritizes risks through deterministic scoring.

The workflow covers:

- External asset discovery
- Identity correlation
- Attack surface inventory
- Exposure discovery
- Brand and email security analysis
- Threat intelligence enrichment
- AI-assisted finding validation
- Risk prioritization
- Unified security reporting

> **Note:** The system is intended for authorized security assessments of explicitly defined target domains. Results represent findings identified by the implemented workflow and should not be interpreted as a guarantee that every possible asset or vulnerability has been identified.

## Project Objectives

The project focuses on four main objectives:

1. **Automate External Attack Surface Discovery**  
   Discover and analyze publicly exposed domains, subdomains, IP addresses, ports, services, web assets, and related external information.

2. **Identify Brand and Email Security Risks**  
   Identify potential lookalike domains and externally observable email-security risks using domain authentication information.

3. **Enrich Security Findings with Threat Intelligence**  
   Add vulnerability and threat context using **NVD, CISA KEV, and EPSS**.

4. **Validate and Prioritize Security Findings**  
   Use AI-assisted validation to assess finding credibility and support false-positive identification, while using deterministic risk scoring for consistent prioritization.

## System Workflow

The system follows a connected processing workflow:

```text
Target Scope
     |
     v
Scope Management
     |
     v
Asset Discovery
     |
     v
Identity Correlation
     |
     v
Attack Surface Inventory
     |
     v
Exposure Discovery
     |
     +----------------------+
     |                      |
     v                      v
Brand & Email          Threat Intelligence
Intelligence           Enrichment
     |                      |
     +----------+-----------+
                |
                v
        AI Finding Validation
                |
                v
        Risk Prioritization
                |
                v
        Unified Reporting
```

Each stage uses structured records associated with a common scope identifier. A shared SQLite database is used to maintain information across the workflow.

## Key Modules

### 1. Scope Management

The system begins by validating and normalizing the target domain and creating a unique scope identifier. This identifier is used to maintain traceability throughout the assessment.

### 2. Asset Discovery

The discovery layer performs external reconnaissance to identify:

- Subdomains
- DNS observations
- IP addresses
- Open ports
- Services
- URLs
- Web-related observations

Multiple discovery sources are used to reduce dependency on a single enumeration tool.

### 3. Identity Correlation and Attack Surface Inventory

Discovered information is correlated using relationships between domains, IP addresses, certificates, ASN information, and other identity-related observations.

The inventory stage normalizes and consolidates these observations into an asset-centric representation and reduces duplicate or overlapping records.

### 4. Exposure Discovery

The system analyzes discovered assets for security exposures using multiple security-analysis techniques, including:

- Vulnerability analysis
- TLS analysis
- Technology identification
- Directory and parameter discovery
- Web security analysis
- Subdomain takeover detection

The resulting observations are normalized into security findings.

### 5. Brand and Email Intelligence

This module analyzes externally observable brand and email-security information, including:

- Lookalike domains
- Lookalike certificates
- SPF
- DKIM
- DMARC
- BIMI

This extends the attack-surface view beyond infrastructure and application security into brand and email-related risks.

### 6. Threat Intelligence Enrichment

Security findings are enriched using:

- **NVD** – CVE and vulnerability metadata
- **CISA KEV** – Known Exploited Vulnerabilities
- **FIRST EPSS** – Exploitability probability

This additional context helps distinguish vulnerability severity from exploitability and known exploitation.

### 7. AI-Assisted Validation and Risk Prioritization

AI is used as a supporting validation mechanism to evaluate the credibility of structured findings, identify potential false positives, and provide remediation guidance.

AI does not act as the sole source of truth. A separate deterministic risk-scoring process calculates the final risk priority using available security and threat context.

### 8. Unified Reporting

The final assessment data is organized into structured reports and can be exported in:

- HTML
- PDF
- XLSX
- JSON
- CSV

## Technology Stack

### Backend

- Python 3.13.2
- FastAPI
- Uvicorn
- SQLAlchemy
- SQLite3
- Pydantic
- asyncio
- aiohttp

### Frontend

- HTML
- CSS
- Vanilla JavaScript

### Security and Reconnaissance Tools

| Category | Tools |
|---|---|
| Subdomain Discovery | subfinder, Amass, Assetfinder, Findomain, shuffledns |
| Port Discovery | Naabu, Nmap, Masscan |
| DNS / Reconnaissance | DNS utilities, crt.sh, HackerTarget |
| Exposure Analysis | Nuclei, Wapiti, Testssl, SSLScan, FFUF, Subzy |
| Web / Technology Analysis | WhatWeb, Webanalyze, wafw00f |
| CMS Analysis | WPScan, JoomScan |
| Threat Intelligence | NVD, CISA KEV, FIRST EPSS |
| AI Validation | Google Gemini API |

## Architecture

The system follows a modular REST-service architecture.

The web interface communicates with the backend through an API gateway. Functional processing stages operate on structured assessment data stored in a shared SQLite database.

```text
Web Interface
      |
      v
API Gateway
      |
      v
Workflow / Backend Services
      |
      +---- Asset Discovery
      +---- Identity Correlation
      +---- Inventory
      +---- Exposure Analysis
      +---- Brand & Email Intelligence
      +---- Threat Intelligence
      +---- AI Validation
      +---- Risk Prioritization
      +---- Reporting
      |
      v
SQLite Database
```

The shared database maintains scope information, discovery observations, correlated identity information, unified assets, exposure findings, threat-intelligence results, validation results, and reporting data.

## Threat Intelligence and Risk Scoring

Threat intelligence provides additional context to security findings through CVE information, known exploitation status, and exploitability probability.

The final risk score uses a deterministic approach and incorporates adjusted finding scores with known exploitation and WAF-related factors.

The resulting score is classified into the following levels:

| Risk Score | Risk Level |
|---:|---|
| 9.0–10.0 | CRITICAL |
| 7.0–8.9 | HIGH |
| 4.0–6.9 | MEDIUM |
| 0.1–3.9 | LOW |
| ≤ 0.0 | INFO |

This separation between **AI-assisted validation** and **deterministic risk scoring** provides a more traceable approach to finding validation and prioritization.

## Example Assessment Results

The implemented workflow produced evidence across multiple assessment stages, including:

- **79** subdomains
- **12** IP addresses
- **15** open ports
- **338** total security findings
- **61** CVE matches
- **2** CISA KEV matches
- **3** EPSS scores
- **104** lookalike domains
- **71** lookalike certificates

These results are consolidated through the reporting layer to provide a unified view of the assessment.

## External Services and Requirements

The implementation uses several external services for reconnaissance, enrichment, and AI-assisted validation.

Required services include:

- Google Gemini API
- Censys API
- NVD
- CISA KEV
- FIRST EPSS
- crt.sh
- HackerTarget

The system requires Internet connectivity because parts of the workflow depend on external reconnaissance and threat-intelligence services.

API credentials may be required for services such as Google Gemini and Censys.

## Project Structure

The implementation is organized around functional workflow stages rather than individual tool outputs:

```text
Scope Management
       |
Asset Discovery
       |
Identity Correlation
       |
Attack Surface Inventory
       |
Exposure Discovery
       |
Brand & Email Intelligence
       |
Threat Intelligence
       |
AI Validation
       |
Risk Prioritization
       |
Unified Reporting
```

The shared database allows each stage to consume structured information generated by earlier stages while maintaining a common assessment scope.

## Testing

The project includes functional testing for the major workflow components, including:

- Scope creation
- Asset discovery
- Identity correlation
- Attack surface inventory
- Exposure discovery
- Threat intelligence enrichment
- Brand and email intelligence
- AI validation
- Unified reporting

Testing also considers subprocess timeouts, API rate limiting, and partial processing failures.

## Project Scope

The project focuses specifically on **externally observable assets and security exposures associated with explicitly defined target domains**.

It is not intended to represent a complete assessment of an organization's entire internal or technology environment. The workflow focuses on external attack-surface discovery and exposure analysis within the defined assessment scope.

## Conclusion

This project integrates established reconnaissance, exposure-analysis, threat-intelligence, AI-assisted validation, risk-prioritization, and reporting techniques into a single automated workflow.

The primary contribution is the **integration of these capabilities into a cohesive External Attack Surface Discovery and Exposure Analysis pipeline**, providing a structured way to discover external assets, correlate security information, enrich findings, validate results, prioritize risks, and generate unified reports.


## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
