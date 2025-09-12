from apscheduler.schedulers.background import BackgroundScheduler
from ActivityTracker.routes import send_email_reminders


def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        func=send_email_reminders,
        trigger="cron",
        day='6-31',  # Exclude days 1 to 5
        hour=9,
        minute=21  # 2:50 PM daily
    )
    scheduler.start()
    print("Scheduler for Email Reminders started")
