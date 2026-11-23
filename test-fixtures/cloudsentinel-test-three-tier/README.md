# cloudsentinel-test-three-tier

Three-tier fixture for the EKS generator: `frontend/` (React UI served by Express on 3000, public) and `backend/`
(Express API on 3001, private) with PostgreSQL. Expected classification: `three-tier`, components `frontend` and
`backend`, RDS `postgres`; only the frontend gets a LoadBalancer Service.
