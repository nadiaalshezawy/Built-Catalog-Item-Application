# Buid an Item Catalog Application Project
The **Catalog project** develop an application that provides a list of items within a variety of categories as well as provide a user registration and authentication system. Registered users will have the ability to post, edit and delete their own items.

## Skills applied
 -Python

 -Flask

 -SQLAchemy

 -OAuth

 -Facebook / Google Login

 -HTML
 
 -CSS
 
 


## Prerequisites
To run this project you need to install python, you'll need database software (provided by a Linux virtual machine) and the database (categoriesitem.db) .

The database includes three tables:

-Category table

-Category-Item table

-User table

## Project content
The project have three python file beside the html templates and css style file:

+database_setup.py : The inital model of  the database.

+lotsofmenus.py : This file will add data to the table ,note that 
                  this data are taken from this
                   [website](https://bagatelleboutique.com/).

+project.py: The main program it will display the application
on the  http://localhost:8000 .The homepage displays all current categories Then the user will navigate into different pages and by logging with google/facebook the user can add/edit/read/update the data displayed.


## How to run

1.Install Vagrant and VirtualBox

2.Clone the [fullstack-nanodegree-vm](https://github.com/udacity/fullstack-nanodegree-vm).

3.Launch the Vagrant VM (vagrant up)

4.Log into Vagrant VM (vagrant ssh)

5.Navigate to cd/vagrant

6.Create the data by running:
  ```python database_setup.py```

    ```python lotsofmenus.py```

7.Run your application within the VM (python /vagrant/catalog2/project.py)
   by typing ```python project.py```

8.Access and test your application by visiting http://localhost:8000 locally

9.When creating new or editting Category/item the name should be unique.

## JSON API ENDPOINT
 The user can have the json api by these url

 Category JSON: `/catalog/<string:category_name>/items/JSON`

 Item JSON: `/catalog/<string:category_name>/<string:category_item>/JSON`

## Contributing

-The application can be modified to have more functionality such as
 image CRUD, recent item added and also the css style can be enhanced.

## Author
 Nadia Ahmed