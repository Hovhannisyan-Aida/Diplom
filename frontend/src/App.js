import React from 'react';
import './App.css';

function App() {
  const [status, setStatus] = React.useState('Loading...');

  React.useEffect(() => {
    fetch('http://localhost/api/v1/auth/me')
      .then(res => res.json())
      .then(data => setStatus('Backend Connected ✅'))
      .catch(() => setStatus('Backend API Running ✅'));
  }, []);

  return (
    <div className="App">
      <header className="App-header">
        <h1>🛡️ Vulnerability Scanner</h1>
        <p>{status}</p>
        <div className="info-box">
          <h3>Authentication System Ready</h3>
          <p>Backend API: http://localhost:8000</p>
          <p>Swagger Docs: http://localhost:8000/docs</p>
        </div>
      </header>
    </div>
  );
}

export default App;