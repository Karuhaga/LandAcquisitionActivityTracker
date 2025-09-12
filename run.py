from ActivityTracker import app
from ActivityTracker.scheduler import start_scheduler


if __name__ == '__main__': #checks if the run.py file has executed directly and not imported
    start_scheduler()  # Start the scheduler when the app runs
    app.run(debug=True)

