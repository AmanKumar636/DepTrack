import React from 'react';
import ReactDOM from 'react-dom';
import App from './App';
import './index.css'; // Import the basic CSS
import { Chart, CategoryScale, LinearScale } from 'chart.js';
Chart.register(CategoryScale, LinearScale);

ReactDOM.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
  document.getElementById('root')
);
