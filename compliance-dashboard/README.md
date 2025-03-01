# CIS AWS Compliance Dashboard

A modern, interactive dashboard for visualizing and managing AWS compliance with the CIS AWS Foundations Benchmark.

![Dashboard Screenshot](screenshot.png)

## Overview

This dashboard provides a beautiful, user-friendly interface for monitoring your AWS resources' compliance with CIS AWS Foundations Benchmark standards. It connects to a backend compliance checking service that evaluates your AWS infrastructure against security best practices.

## Features

- **Interactive Dashboard**: Visualize compliance scores with charts and statistics
- **Detailed Control View**: Explore all compliance controls with filtering and sorting
- **Historical Tracking**: Monitor compliance progress over time
- **One-click Remediation**: Fix non-compliant resources with automated remediation
- **Customizable Settings**: Configure scan schedules and notifications
- **Responsive Design**: Works seamlessly on desktop and mobile devices

## Tech Stack

- **React**: Frontend library for building user interfaces
- **Redux Toolkit**: State management with simplified Redux patterns
- **AWS Amplify**: Authentication and API integration with AWS services
- **Chart.js**: Interactive data visualization
- **TailwindCSS**: Utility-first CSS framework for styling
- **React Router**: Client-side routing

## Prerequisites

- Node.js 14+ and npm/yarn
- AWS account with appropriate permissions
- Backend compliance service (see backend repository)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/cis-compliance-dashboard.git
   cd cis-compliance-dashboard
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure AWS Amplify:
   Edit `src/index.js` to update the Amplify configuration with your AWS resources:
   ```javascript
   const awsConfig = {
     Auth: {
       region: 'YOUR_REGION',
       userPoolId: 'YOUR_USER_POOL_ID',
       userPoolWebClientId: 'YOUR_CLIENT_ID',
     },
     API: {
       endpoints: [
         {
           name: 'complianceApi',
           endpoint: 'YOUR_API_ENDPOINT',
           region: 'YOUR_REGION'
         }
       ]
     }
   };
   ```

4. Start the development server:
   ```bash
   npm start
   ```

## Deployment

### AWS Amplify Hosting
1. Push your repository to GitHub/GitLab/Bitbucket
2. Connect your repository in the AWS Amplify Console
3. Configure build settings and deploy

### S3 Static Hosting with CloudFront
1. Build the production bundle:
   ```bash
   npm run build
   ```

2. Deploy to S3:
   ```bash
   aws s3 sync build/ s3://your-bucket-name --acl public-read
   ```

3. Create a CloudFront distribution pointing to your S3 bucket

## Project Structure

```
compliance-dashboard/
├── public/                 # Public assets
├── src/
│   ├── components/         # Reusable components
│   ├── pages/              # Page components
│   ├── store/              # Redux store setup and slices
│   ├── utils/              # Utility functions
│   ├── api/                # API service functions
│   ├── App.js              # Main app component
│   └── index.js            # Entry point
└── README.md               # Project documentation
```

## Backend Integration

The dashboard connects to a serverless backend that performs compliance checks using AWS Lambda. The backend repository provides the necessary API endpoints for:

- Running compliance scans
- Retrieving compliance results
- Executing remediation actions
- Managing configuration settings

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services/)
- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)
- [React](https://reactjs.org/)
- [Chart.js](https://www.chartjs.org/)
- [Tailwind CSS](https://tailwindcss.com/) 