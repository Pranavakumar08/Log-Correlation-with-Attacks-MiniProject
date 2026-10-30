// API Client for Insider Threat SIEM REST endpoints

const API = {
    async getStatus() {
        const res = await fetch('/api/status');
        return await res.json();
    },

    async startSimulation() {
        const res = await fetch('/api/simulation/start', { method: 'POST' });
        return await res.json();
    },

    async pauseSimulation() {
        const res = await fetch('/api/simulation/pause', { method: 'POST' });
        return await res.json();
    },

    async resetSimulation() {
        const res = await fetch('/api/simulation/reset', { method: 'POST' });
        return await res.json();
    },

    async setSpeed(speed) {
        const res = await fetch('/api/simulation/speed', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ speed: parseFloat(speed) })
        });
        return await res.json();
    },

    async triggerScenario(scenario) {
        const res = await fetch('/api/simulation/trigger-scenario', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scenario })
        });
        return await res.json();
    },

    async injectCustomLog(payload) {
        const res = await fetch('/api/simulation/inject-log', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        return await res.json();
    },

    async getLogs(limit = 60, source = '', user = '') {
        const params = new URLSearchParams();
        if (limit) params.append('limit', limit);
        if (source) params.append('source', source);
        if (user) params.append('user', user);
        const res = await fetch(`/api/logs?${params.toString()}`);
        return await res.json();
    },

    async getIncidents(severity = '') {
        const params = new URLSearchParams();
        if (severity && severity !== 'ALL') params.append('severity', severity);
        const res = await fetch(`/api/incidents?${params.toString()}`);
        return await res.json();
    },

    async getIncidentDetails(incidentId) {
        const res = await fetch(`/api/incidents/${incidentId}`);
        return await res.json();
    },

    async updateIncidentStatus(incidentId, status) {
        const res = await fetch(`/api/incidents/${incidentId}/status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status })
        });
        return await res.json();
    },

    async getUsers() {
        const res = await fetch('/api/users');
        return await res.json();
    },

    async getRules() {
        const res = await fetch('/api/rules');
        return await res.json();
    }
};
