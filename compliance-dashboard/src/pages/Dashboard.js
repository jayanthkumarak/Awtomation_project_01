import React from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { Link } from 'react-router-dom';
import { Doughnut, Bar } from 'react-chartjs-2';
import { Chart, ArcElement, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend } from 'chart.js';
import { runScan } from '../store/complianceSlice';

// Register Chart.js components
Chart.register(ArcElement, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

// Utility function to get color based on score
const getScoreColor = (score) => {
  if (score >= 80) return 'bg-green-100 text-green-800';
  if (score >= 60) return 'bg-yellow-100 text-yellow-800';
  return 'bg-red-100 text-red-800';
};

const Dashboard = () => {
  const dispatch = useDispatch();
  const { complianceScore, categoryScores, latestResults, loading } = useSelector(state => state.compliance);
  
  const handleRunScan = () => {
    dispatch(runScan());
  };
  
  // Prepare data for donut chart
  const donutData = {
    labels: ['Passing', 'Failing'],
    datasets: [
      {
        data: [complianceScore, 100 - complianceScore],
        backgroundColor: ['#34D399', '#F87171'],
        borderColor: ['#10B981', '#EF4444'],
        borderWidth: 1,
        hoverOffset: 4,
      },
    ],
  };
  
  // Prepare data for category bar chart
  const categoryNames = Object.keys(categoryScores);
  const categoryScoreValues = categoryNames.map(cat => categoryScores[cat].score);
  
  const barData = {
    labels: categoryNames,
    datasets: [
      {
        label: 'Compliance Score by Category',
        data: categoryScoreValues,
        backgroundColor: categoryScoreValues.map(score => 
          score >= 80 ? 'rgba(52, 211, 153, 0.8)' : 
          score >= 60 ? 'rgba(251, 191, 36, 0.8)' : 
          'rgba(248, 113, 113, 0.8)'
        ),
        borderWidth: 1,
      },
    ],
  };
  
  // Count controls by status
  const statusCounts = Object.values(latestResults).reduce(
    (counts, result) => {
      counts[result.status] = (counts[result.status] || 0) + 1;
      return counts;
    },
    {}
  );
  
  return (
    <div className="dashboard">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold text-gray-800">Dashboard</h1>
        <button
          onClick={handleRunScan}
          disabled={loading}
          className="bg-blue-600 hover:bg-blue-700 text-white py-2 px-4 rounded-md flex items-center"
        >
          {loading ? 'Scanning...' : 'Run New Scan'}
          {loading && <span className="ml-2 animate-spin">⟳</span>}
        </button>
      </div>
      
      {/* Overall Compliance Score */}
      <div className="dashboard-card">
        <h2>Overall Compliance Score</h2>
        <div className="flex items-center mb-4">
          <div className={`text-4xl font-bold mr-6 ${getScoreColor(complianceScore)}`}>
            {complianceScore}%
          </div>
          <div className="w-48 h-48">
            <Doughnut 
              data={donutData} 
              options={{
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                  legend: {
                    position: 'bottom',
                  },
                },
              }}
            />
          </div>
        </div>
      </div>
      
      {/* Status Summary */}
      <div className="dashboard-card">
        <h2>Control Status Summary</h2>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-4">
          <div className="bg-green-50 p-4 rounded-lg">
            <div className="text-xl font-semibold text-green-800">
              Passing Controls
            </div>
            <div className="text-3xl font-bold text-green-600">
              {statusCounts.PASS || 0}
            </div>
          </div>
          <div className="bg-red-50 p-4 rounded-lg">
            <div className="text-xl font-semibold text-red-800">
              Failing Controls
            </div>
            <div className="text-3xl font-bold text-red-600">
              {statusCounts.FAIL || 0}
            </div>
          </div>
          <div className="bg-yellow-50 p-4 rounded-lg">
            <div className="text-xl font-semibold text-yellow-800">
              Error Controls
            </div>
            <div className="text-3xl font-bold text-yellow-600">
              {statusCounts.ERROR || 0}
            </div>
          </div>
        </div>
        <Link 
          to="/controls"
          className="text-blue-600 hover:text-blue-800 hover:underline font-medium"
        >
          View all controls →
        </Link>
      </div>
      
      {/* Category Scores */}
      <div className="dashboard-card">
        <h2>Compliance by Category</h2>
        <div className="h-80 mb-4">
          <Bar 
            data={barData} 
            options={{
              responsive: true,
              maintainAspectRatio: false,
              scales: {
                y: {
                  beginAtZero: true,
                  max: 100,
                  ticks: {
                    callback: function(value) {
                      return value + '%';
                    }
                  }
                }
              },
              plugins: {
                legend: {
                  display: false,
                },
                tooltip: {
                  callbacks: {
                    label: function(context) {
                      return context.parsed.y + '%';
                    }
                  }
                }
              }
            }}
          />
        </div>
        
        {/* Category details in small print */}
        <div className="text-sm text-gray-600">
          {categoryNames.map(cat => (
            <div key={cat} className="flex justify-between items-center mb-1">
              <span>{cat}</span>
              <span className={`font-medium ${getScoreColor(categoryScores[cat].score)}`}>
                {categoryScores[cat].passing} / {categoryScores[cat].total} ({categoryScores[cat].score}%)
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default Dashboard; 