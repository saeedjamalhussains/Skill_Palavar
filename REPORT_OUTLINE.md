# Project Report: ZTNA Integrated Secure Banking System

## 1. Introduction
- Background of Zero Trust Architecture
- Problem Statement: Traditional perimeter-based security in banking.
- Objectives: Continuous verification and granular access control.

## 2. System Architecture
- **Backend**: FastAPI Micro-modular design.
- **Database**: PostgreSQL with SQLAlchemy ORM.
- **Security**: JWT, MFA, and ZTNA Risk Engine.
- **Frontend**: Responsive Dashboard with Real-time Feedback.

## 3. ZTNA Implementation
- Contextual Risk Assessment (Identity, Device, Context).
- Trust Score Calculation.
- Policy Enforcement Points (PEP).

## 4. RBAC & Hierarchical Control
- Role Mapping and Inheritance.
- Permission Matrices for Banking Roles.
- Tiered Approval Workflow.

## 5. Security Analysis
- Mitigation of Session Hijacking.
- Defense against unauthorized horizontal/vertical movement.
- Audit Trails and Non-repudiation.

## 6. Deployment & Testing
- Automated Unit Tests.
- Cloud Migration Strategy (Local to AWS).
- Performance Benchmarks.

## 7. Conclusion & Future Scope
- Integration with Biometric Identity.
- AI-based Anomaly Detection in ZTNA.
