# Oak Dental Hospital

Oak Dental Hospital is a web application for managing dental appointments, treatments, and hospital timings. It provides a user-facing interface for booking appointments and an admin panel for managing operations. Built with Node.js, Express, PostgreSQL, and Razorpay for payments, the app uses Tailwind CSS for styling and is inspired by Manya Dental's design.

## Features
- **User Interface** (`/`):
  - Browse dental treatments with prices, images, and videos.
  - Book appointments with Razorpay payment integration.
  - Manage appointments (view, cancel, reschedule) using a phone number.
  - View hospital timings and contact details.
- **Admin Interface** (`/admin`):
  - Admin login and registration with JWT authentication.
  - Manage appointments (approve, cancel with reasons).
  - Add, edit, or delete treatments with image/video uploads.
  - Update hospital timings.
- **Backend**:
  - RESTful API for appointments, treatments, timings, and payments.
  - PostgreSQL database for data storage.
  - File uploads for treatment media using Multer.
  - Secure payment processing with Razorpay.

## Prerequisites
- **Node.js**: v18 or higher
- **PostgreSQL**: v13 or higher
- **Razorpay Account**: For payment integration
- **Git**: For version control
- **GitHub Account**: For repository hosting
- **Environment Variables**:
  - PostgreSQL connection details (`PG_USER`, `PG_HOST`, `PG_DATABASE`, `PG_PASSWORD`, `PG_PORT`)
  - Razorpay API keys (`RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`)
  - JWT secret (`JWT_SECRET`)

## Project Structure

oak/├── public/│   ├── index.html       # User-facing page│   ├── admin.html       # Admin panel│   ├── Uploads/         # Folder for treatment images/videos├── server.js            # Express backend├── .env                 # Environment variables (not in Git)├── .gitignore           # Files to ignore in Git├── package.json         # Dependencies and scripts├── README.md            # This file

## Getting Started: From Clone to GitHub Push

### 1. Clone the Repository
If you don't have a repository yet, create one on GitHub:
- Go to `github.com`, sign in, and click "New repository."
- Name it (e.g., `oak-dental`), set it to public or private, and initialize with a README (optional).
- Copy the repository URL (e.g., `https://github.com/your-username/oak-dental.git`).

Clone the repository to your local machine:
```bash
git clone https://github.com/your-username/oak-dental.git
cd oak-dental

If starting from scratch, initialize a new Git repository:
mkdir oak-dental
cd oak-dental
git init

2. Set Up the Project

Create Project Files:

Ensure the following files are in oak-dental/:
server.js: Express backend (from your project).
public/index.html: User interface.
public/admin.html: Admin interface.
package.json: Project metadata and dependencies.


Create the public/Uploads folder if not present:mkdir public
mkdir public/Uploads




Initialize package.json (if not present):
npm init -y

Update package.json with:
{
  "name": "oak-dental",
  "version": "1.0.0",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "pg": "^8.11.3",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "dotenv": "^16.3.1",
    "cors": "^2.8.5",
    "multer": "^1.4.5-lts.1",
    "razorpay": "^2.9.2"
  }
}


Install Dependencies:
npm install


Create .gitignore:Create a .gitignore file to exclude sensitive files:
echo -e "node_modules/\n.env\npublic/Uploads/" > .gitignore


Set Up Environment Variables:Create a .env file in oak-dental/:
PG_USER=your_postgres_user
PG_HOST=your_postgres_host
PG_DATABASE=your_postgres_database
PG_PASSWORD=your_postgres_password
PG_PORT=5432
RAZORPAY_KEY_ID=your_razorpay_key_id
RAZORPAY_KEY_SECRET=your_razorpay_key_secret
JWT_SECRET=your_jwt_secret
PORT=3000

Replace placeholders with your PostgreSQL, Razorpay, and JWT details.

Set Up PostgreSQL:

Install PostgreSQL locally or use a cloud provider (e.g., ElephantSQL, Render PostgreSQL).
Create a database (e.g., oak_dental).
The server.js initializeDatabase function creates tables on startup.
If you encounter schema issues (e.g., missing price or approved columns), run:ALTER TABLE appointments
ADD COLUMN IF NOT EXISTS price DECIMAL(10,2) NOT NULL DEFAULT 0.00,
ADD COLUMN IF NOT EXISTS approved BOOLEAN DEFAULT FALSE;





3. Run Locally

Start the Server:
node server.js


Expect logs: Database initialized and 🚀 Server running on http://localhost:3000.


Access the Application:

User Link: http://localhost:3000/
Loads index.html for booking and browsing.


Admin Link: http://localhost:3000/admin
Loads admin.html for admin management.




Test Functionality:

User Side: Book an appointment (e.g., “TEETH CLEANING”), test Razorpay payment, and manage appointments.
Admin Side: Register an admin, log in, approve appointments, add treatments, and update timings.
Check server logs for errors (e.g., database or Razorpay issues).



4. Commit Changes

Stage Files:
git add .


Commit Changes:
git commit -m "Initial setup with user and admin interfaces"



5. Push to GitHub

Link to GitHub (if not cloned):

Create a repository on GitHub (e.g., oak-dental).
Link your local repo:git remote add origin https://github.com/your-username/oak-dental.git
git branch -M main




Push to GitHub:
git push -u origin main


If prompted, authenticate with your GitHub credentials.
Verify the code appears on GitHub (https://github.com/your-username/oak-dental).



Deployment (Optional)
To make the app accessible online, deploy to a platform like Render:

Push to GitHub: Ensure your code is on GitHub (see above).
Create Render Web Service:
Sign up at render.com.
Click “New” → “Web Service” and connect your GitHub repo.
Configure:
Environment: Node
Branch: main
Build Command: npm install
Start Command: npm start




Set Environment Variables in Render:
Add PG_USER, PG_HOST, PG_DATABASE, PG_PASSWORD, PG_PORT, RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET, JWT_SECRET, PORT.


Deploy:
Click “Create Web Service”.
Get URLs:
User Link: https://your-app.onrender.com/
Admin Link: https://your-app.onrender.com/admin





Troubleshooting

Admin Link Loads index.html:
Ensure admin.html is in public/.
Check server logs for GET /admin.
Clear browser cache (Ctrl + Shift + R).


Database Errors:
Verify PostgreSQL connection in .env.
Run ALTER TABLE commands if columns are missing (see Setup).


Razorpay Issues:
Confirm RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET.
Test in Razorpay’s test mode.


Git Push Fails:
Ensure correct remote URL (git remote -v).
Check GitHub credentials or SSH key setup.



Security Notes

HTTPS: Use a platform with HTTPS (e.g., Render).
Environment Variables: Exclude .env from Git (echo ".env" >> .gitignore).
CORS: Restrict origins in production:app.use(cors({ origin: 'https://your-app.onrender.com' }));


Rate Limiting: Add express-rate-limit:const rateLimit = require('express-rate-limit');
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));



Contributing

Fork the repo.
Create a feature branch (git checkout -b feature/your-feature).
Commit changes (git commit -m "Add your feature").
Push (git push origin feature/your-feature).
Open a pull request.

License
© 2025 Oak Dental Hospital. All rights reserved.
Contact

Email: info@oakdentalhospital.com
Phone: +91-7569 366 767
WhatsApp: https://wa.me/+917569366767



