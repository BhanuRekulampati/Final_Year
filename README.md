# AI Decision Platform

A comprehensive AI-powered decision-making platform with three main features:
- **Gadget Analyzer**: Smart gadget purchasing decisions
- **College Admission Advisor**: College admission guidance
- **Stock Market Decision Maker**: Investment recommendations

## Features

### 🎯 Gadget Analyzer
- Enter any gadget name for instant analysis
- Get detailed pros and cons
- Current market trend analysis
- Newer model suggestions
- Dark/Light theme support

### 🎓 College Admission Advisor
- AI-powered admission chance analysis
- Stream recommendations based on academic profile
- Comprehensive college guidance

### 📈 Stock Market Decision Maker
- Investment portfolio analysis
- Stock market recommendations
- Risk assessment

## Tech Stack

- **Backend**: Flask (Python)
- **Frontend**: HTML, CSS, JavaScript
- **Styling**: Tailwind CSS, Custom CSS
- **Icons**: Font Awesome
- **Deployment**: Render

## Local Development

1. **Clone the repository**
   ```bash
   git clone <your-repo-url>
   cd Final_Year
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python src/app.py
   ```

4. **Access the application**
   - Open http://localhost:5000
   - Navigate to different features using the navigation menu

## Deployment to Render

### Method 1: Using Render Dashboard (Recommended)

1. **Push your code to GitHub**
   ```bash
   git add .
   git commit -m "Ready for deployment"
   git push origin main
   ```

2. **Deploy on Render**
   - Go to [render.com](https://render.com)
   - Sign up/Login with your GitHub account
   - Click "New +" → "Web Service"
   - Connect your GitHub repository
   - Configure the service:
     - **Name**: `ai-decision-platform`
     - **Environment**: `Python 3`
     - **Build Command**: `chmod +x render-build.sh && ./render-build.sh`
     - **Start Command**: `gunicorn --bind 0.0.0.0:$PORT --workers 2 --threads 4 src.app:app`
   - Click "Create Web Service"

### Method 2: Using render.yaml (Blue-Green Deployment)

1. **The `render.yaml` file is already configured**
2. **Deploy using Render CLI or Dashboard**
   - Render will automatically detect the `render.yaml` file
   - Follow the prompts to deploy

## Environment Variables

The application uses these environment variables (automatically set by Render):
- `PORT`: Port number (set by Render)
- `PYTHON_VERSION`: Python version (3.11.9)

## File Structure

```
Final_Year/
├── src/
│   ├── app.py              # Main Flask application
│   ├── decision_maker.py   # Decision making logic
│   ├── main.py            # Entry point
│   └── templates/         # HTML templates
│       ├── base.html      # Base template with navigation
│       ├── dashboard.html # Dashboard page
│       ├── gadget_analyzer.html # Gadget analysis page
│       ├── admission.html # College admission page
│       └── ...
├── requirements.txt       # Python dependencies
├── Procfile             # Process file for deployment
├── render-build.sh      # Build script for Render
├── render.yaml          # Render configuration
└── runtime.txt          # Python runtime version
```

## Features

### 🌙 Dark Theme Support
- Toggle between light and dark themes
- Persistent theme preference
- Optimized for all pages

### 📱 Responsive Design
- Mobile-friendly interface
- Modern glass-morphism design
- Smooth animations and transitions

### 🔒 Security
- Input validation
- Secure form handling
- Error handling

## Troubleshooting

### Common Issues

1. **Build fails on Render**
   - Check Python version compatibility
   - Verify all dependencies in `requirements.txt`
   - Check build logs for specific errors

2. **Application not starting**
   - Verify the start command in Procfile
   - Check if port is properly configured
   - Review application logs

3. **Static files not loading**
   - Ensure all templates are in the correct directory
   - Check file paths in templates

### Support

For deployment issues:
1. Check Render documentation
2. Review build and runtime logs
3. Verify all configuration files are present

## License

This project is part of a B.Tech Final Year Project.

---

**Deployed URL**: Your application will be available at `https://your-app-name.onrender.com` after successful deployment.
