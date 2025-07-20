# MediDash

MediDash is a Django-based medical dashboard platform designed to streamline healthcare management for doctors, patients, and administrators. It provides secure user authentication, profile management, device integration, health record uploads, notifications, and more.

## Features
- **Role-based access:** Separate dashboards and permissions for doctors, patients, and admins.
- **Doctor features:**
  - Manage profile and settings
  - View and manage patients
  - Add/view medical records and reports
  - Receive and manage alerts and notifications
- **Patient features:**
  - View health records and vitals history
  - Manage profile and notification preferences
  - Secure messaging with doctors
- **Admin features:**
  - Register/manage users and devices
  - View all records and system notifications
  - Site-wide settings management
- **Device integration:** Upload and view vital signs from medical devices (e.g., ESP32-based sensors)
- **Customizable settings:** Theme, notification preferences, and more

## Setup Instructions

### Prerequisites
- Python 3.8+
- pip
- (Recommended) Virtual environment tool (venv, virtualenv, etc.)

### Installation
1. **Clone the repository:**
   ```bash
   git clone https://github.com/Mohammad-Ikhlas-khan/Remote_Health_Monitoring
   cd medidash_project
   ```
2. **Create and activate a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
4. **Apply migrations:**
   ```bash
   python manage.py migrate
   ```
5. **Create a superuser (admin):**
   ```bash
   python manage.py createsuperuser
   ```
6. **Run the development server:**
   ```bash
   python manage.py runserver
   ```
7. **Access the app:**
   - Open [http://127.0.0.1:8000/](http://127.0.0.1:8000/) in your browser.

## Project Structure
```
medidash_project/
  manage.py
  medidash/           # Main Django app (models, views, forms, etc.)
  medidash_project/   # Django project settings
  static/             # Static files (CSS, images)
  templates/          # HTML templates
  profile_pics/       # Uploaded profile pictures
  db.sqlite3          # SQLite database (default)
  requirements.txt    # Python dependencies
```

## Customization
- **Add specialties, themes, or formats:** Edit `DoctorUpdateForm` in `medidash/forms.py`.
- **Static and template files:** Customize UI in `static/` and `templates/`.

## Notes
- For production, configure environment variables, static/media file serving, and use a production-ready database.
- Device integration (e.g., ESP32) expects data at `/api/esp32/vital/`.

## License
This project is for educational/demo purposes. Add your license as needed. 