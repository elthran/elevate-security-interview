# elevate-security-interview

This application was built and tested on Python 3.8

# Installing the App

To be able to run the app you will first need to make sure you are in the 
`elevate-security-interview` directory and create a new virtual environment. 
Then run `pip3 install -r requirements.txt` to ensure that all required packages are installed.

# Running the App

To start the server you need to run
`python3 manage.py runserver 9000` 
*Note:* for Windows you may need to use `python manage.py runserver 9000`

Once the console logs "Saved data as JSON", the server is ready.

To fetch data simply visit `http://127.0.0.1:9000/incidents/`

# About the App

The App is quite simple. It runs one thread running the `Scheduled` App that runs in the 
background and fetches data every 20 minutes. This data is stored in a database with two tables:
`employees` which is has one row per employee with their employee_id and their IP
`incidents` which has one row per incident and the information about it
A report is also generated from these tables and is saved as a JSON file.

The main thread runs the Incident app which hosts an API that simply returns the JSON file when called.

# TODO

As this was a quick assignment, there is of course a lot of improvements that could be made:
- The most obvious is adding the .env file to .gitignore and not passing credentials across git.
- The next most obvious is that there is no handling for multiple employees who share an IP address.
This would need to be addressed in any production version.
- We are rebuilding the tables on each fetch which is not ideal. It should append and update rows.
- Currently the data to be fetched is prepared and stored in a file for faster retrieval. 
On a more complex API we would need to come up with a better strategy 
(like exposing lightweight versions of our tables or storing the report as a variable depending on priority)
- Adding unit tests. If I had more time that would have been the next thing to add to make sure that changes
to the code don't modify the fetching or reporting functionality.
- Remove the .db file from the repo and force new users to run the migrations themselves