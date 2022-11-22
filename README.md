# Bugs
    
## Project Description
This project is an issue tracker project. It enables the user to 
perform the following actions:
<li>
create a bug
</li>
<li>
Assign the bug to another user
</li>
<li>
Resolve the bug by updating the bug status
</li>
<li>
Comments can be made to a bug
</li>

##  Project Setup
<li>Clone the project first from github.</li>
<li>Open the terminal. Then type this command <code>
pip install virtualenvwrapper</code>, this will enable you to 
create virtual environments</li>
<li>Then type the following commands
<code>mkvirtualenv {{ Name of the virtual environment}} </code>,
the name can be anything example <code>mkvirtualenv venv</code>
<li>After running that command, type
<code>workon {{ Name of the virtual environment }} </code>, 
to activate that virtual environment.</li>
<li>Type the next command <code>pip install -r requirements.txt</code>,
to install the dependencies for the project.
</li>
<li>Navigate to the root of project and open 
<code>.env.sample</code> file, copy the contents and create 
a <code>.env</code> file, then paste the contents into it. Those 
are your environment variables. You can modify the values if you wish,
but ensure that the keys are the same.</li>
<li>Type this command <code>python manage.py makemigrations</code>,
to create the first database migrations and then run 
<code>python manage.py migrate</code> to commit the migrations into the database.
</li>
<li>
    Type in this command <code>python manage.py runserver localhost:8000</code>
        The server should start running.
</li>
<li>
    Go to your browser and navigate to <a href="http://localhost:8000/docs/">http://localhost:8000/docs/</a>
to view the swagger API documentation with which you can use to work with
the APIs.
</li>

### Enjoy !!!