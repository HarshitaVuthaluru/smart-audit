# Smart Contract Vulnerability Analyzer Frontend

This is a React-based frontend for the Smart Contract Vulnerability Analyzer system.

## Setup

### Backend
1. Navigate to the frontend_poc directory
2. Install dependencies:
   ```
   pip install flask flask-socketio flask-cors
   ```
3. Run the backend:
   ```
   python app.py
   ```

### Frontend
1. Navigate to the frontend_poc/client directory
2. Install dependencies:
   ```
   npm install
   ```
3. Run the development server:
   ```
   npm start
   ```

## Features
- Upload Solidity contracts or fetch them by address
- Choose models for each agent in the analysis process
- Visualize the multi-agent workflow in real-time
- View detected vulnerabilities with details and confidence scores
- Explore exploit plans and proof-of-concept code
- Track the execution results of generated exploits

## Structure
- `app.py`: Flask backend that interfaces with the core analysis system
- `client/`: React frontend application
  - `src/components/`: UI components
  - `src/services/`: API and WebSocket services
  - `src/pages/`: Main application pages
  - `src/context/`: React context providers
  - `src/visualizer/`: Agent workflow visualization components

## Technologies Used
- **Frontend**: React, Tailwind CSS, Socket.io client, React Flow
- **Backend**: Flask, Flask-SocketIO, Flask-CORS

## API Endpoints
- `POST /api/upload-contract`: Upload a Solidity file
- `POST /api/fetch-contract`: Fetch contract from blockchain by address
- `POST /api/analyze`: Start analysis with options
- `GET /api/status/:jobId`: Get analysis status
- `GET /api/results/:jobId`: Get analysis results