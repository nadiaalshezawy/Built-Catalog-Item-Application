#!/usr/bin/env python3
# Build An Item Catalog project
# Done by : Nadia Ahmed
from flask import Flask, render_template, request
from flask import redirect, jsonify, url_for, flash
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import exists
from database_setup import CategoryItem, Base, Category, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "catalog item"
engine = create_engine('sqlite:///categoriesitem.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)
    # return "The current session state is %s" % login_session['state']


# facebook login url
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print ("access token received %s " % access_token)
    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = (
          'https://graph.facebook.com/oauth/access_token?grant_type'
          '=fb_exchange_token&client_id=%s&client_secret=%s'
          '&fb_exchange_token=%s') % (
          app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token
        exchange we have to split the token first on commas and
        select the first index which gives us the key : value
        for the server access token then we split it on colons
        to pull out the actual token value and replace the remaining
        quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = (
           'https://graph.facebook.com/v2.8/me?'
           'access_token=%s&fields=name,id,email') % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url1 = 'https://graph.facebook.com/v2.8/me/picture?access_token='
    url = url1+'%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += (
              ' " style = "width: 300px; height: 300px;border-radius: 150px;'
              '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> ')

    flash("Now logged in as %s" % login_session['username'])
    return output


# facebook disconnect url
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = (
          'https://graph.facebook.com/%s/permissions?'
          'access_token=%s') % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# google sign in
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print ("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
                        json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px; '
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;">'
    flash("you are now logged in as %s" % login_session['username'])
    print ("done!")
    return output


# disconnect google user
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(
                    json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCatalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalog'))


# User Helper Functions
def createUser(login_session):
    newUser = User(
              name=login_session['username'], email=login_session['email'])
    print ("name :"+login_session['username'])
    print ("email :"+login_session['email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Show json endpoint for category
@app.route('/catalog/<string:category_name>/items/JSON')
def categoyItemJSON(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(
                CategoryItem).filter_by(category_id=category.id).all()
    return jsonify(CategoryItem=[i.serialize for i in items])


# Show json endpoint for item
@app.route('/catalog/<string:category_name>/<string:category_item>/JSON')
def itemJSON(category_name, category_item):
    item = session.query(CategoryItem).filter_by(name=category_item).one()
    return jsonify(MenuItem=item.serialize)


# Show main page catalog
@app.route('/')
@app.route('/catalog/')
def showCatalog():
    categories = session.query(Category).all()
    if 'username' not in login_session:
        return render_template('publicshowCatalog.html', categories=categories)
    else:
        return render_template('showCatalog.html', categories=categories)
    # return "This page will show main page catalog"


# Create a new category
@app.route('/category/new/', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        categories = session.query(Category).all()
        # check if the category exist
        for cat in categories:
            if cat.name == request.form['name']:
                flash("The name is existed. choose another name")
                return render_template('newCategory.html')
        newCategory = Category(name=request.form['name'],
                               user_id=login_session['user_id'])
        session.add(newCategory)
        session.commit()
        flash("new Category is added!")
        return redirect(url_for('showCatalog'))
    else:
        return render_template('newCategory.html')
    # return "This page will be create new category"


# Edit a Category
@app.route('/catalog/<string:category_name>/edit/', methods=['GET', 'POST'])
def editCategory(category_name):
    if 'username' not in login_session:
        return redirect('/login')
    editedCategory = session.query(
        Category).filter_by(name=category_name).one()
    if editedCategory.user_id != login_session['user_id']:
        return """<script>function myFunction() {alert(
                 'You are not authorized to edit this category.');
                  }</script><body onload='myFunction()'>"""
    if request.method == 'POST':
        categories = session.query(Category).all()
        # check if the category editting name exist
        for cat in categories:
            if cat.name == request.form['name']:
                flash("The name is existed. choose another name")
                return render_template(
                     'editCategory.html', category=editedCategory)
        editedCategory.name = request.form['name']
        session.add(editedCategory)
        session.commit()
        flash("Category was editted!")
        return redirect(url_for('showCatalog'))
    else:
        return render_template(
            'editCategory.html', category=editedCategory)
    # return 'This page will be for editing category %s' % category_name


# Delete a Category
@app.route('/catalog/<string:category_name>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_name):
    if 'username' not in login_session:
        return redirect('/login')
    categoryToDelete = session.query(
        Category).filter_by(name=category_name).one()
    if categoryToDelete.user_id != login_session['user_id']:
        return """<script>function myFunction() {alert(
                 'You are not authorized to delete this category.');
                 }</script><body onload='myFunction()'>"""
    if request.method == 'POST':
        session.delete(categoryToDelete)
        session.commit()
        flash("Category was deleted!")
        return redirect(
            url_for('showCatalog', category_id=categoryToDelete.id))
    else:
        return render_template(
            'deleteCategory.html', category=categoryToDelete)
    # return 'This page will be for deleting category %s' % category_name


# Show a category all items
@app.route('/catalog/<string:category_name>/')
@app.route('/catalog/<string:category_name>/items/')
def showAllItems(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(
            CategoryItem).filter_by(category_id=category.id).all()
    creator = getUserInfo(category.user_id)
    # if user not login show the public page
    if 'username' not in login_session:
        return render_template(
                   'publicItems.html', category=category, items=items)
    else:
        return render_template(
                   'showAllItems.html', category=category, items=items)
    # return 'This page will show items for catgeory %s' % category_name


# Add item to category
@app.route('/catalog/<string:category_name>/new', methods=['GET', 'POST'])
def newItem(category_name):
    if 'username' not in login_session:
        return redirect('/login')
    categoryToAdd = session.query(
        Category).filter_by(name=category_name).one()
    if request.method == 'POST':
        items = session.query(
            CategoryItem).filter_by(category_id=categoryToAdd.id).all()
        # check if the category name  exist
        for item in items:
            if item.name == request.form['name']:
                flash("The name is existed. choose another name")
                return render_template('newItem.html')
        newItem = CategoryItem(
                            name=request.form['name'], description=request.form
                            ['description'], price=request.form['price'],
                            category_id=categoryToAdd.id,
                            user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash("new item added!")
        return redirect(url_for('showAllItems', category_name=category_name))
    else:
        return render_template('newItem.html', category_name=category_name)
    # return 'This page will add item to %s' % category_name


# Read a category item
@app.route('/catalog/<string:category_name>/<string:category_item>/read/')
def readItem(category_name, category_item):
    itemToRead = session.query(
        CategoryItem).filter_by(name=category_item).one()
    creator = getUserInfo(itemToRead.user_id)
    # show private page for creator of item while login
    if 'username' not in login_session or (
            creator.id != login_session['user_id']):
        return render_template('publicreadItem.html',
                               category_name=category_name, item=itemToRead)
    else:
        return render_template(
             'readItem.html', category_name=category_name, item=itemToRead)


# Edit a category item
@app.route('/catalog/<string:category_name>/<string:category_item>/edit',
           methods=['GET', 'POST'])
def editItem(category_name, category_item):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(
                 CategoryItem).filter_by(name=category_item).one()
    # check if owner of item before editting
    if editedItem.user_id != login_session['user_id']:
        return """<script>function myFunction() {alert(
               'You are not authorized to edit this item.');}
               </script><body onload='myFunction()'>"""
    if request.method == 'POST':
        items = session.query(
            CategoryItem).filter_by(category_id=editedItem.category_id).all()
        # check if the editted new name exist
        for item in items:
            if item.name == request.form['name']:
                flash("The name is existed. choose another name")
                return render_template(
                        'editItem.html', category_id=editedItem.category_id,
                        item_id=editedItem.id, item=editedItem)
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['name']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['category_id']:
            editedItem.category_id = request.form['category_id']
        if request.form['user_id']:
            editedItem.user_id = request.form['user_id']
        session.add(editedItem)
        session.commit()
        flash("Item is editted!")
        return redirect(url_for('showAllItems', category_name=category_name))
    else:
        return render_template(
               'editItem.html', category_id=editedItem.category_id,
               item_id=editedItem.id, item=editedItem)


# Delete a category item
@app.route('/catalog/<string:category_name>/<string:category_item>/delete/',
           methods=['GET', 'POST'])
def deleteItem(category_name, category_item):
    if 'username' not in login_session:
        return redirect('/login')
    itemToDelete = session.query(
                   CategoryItem).filter_by(name=category_item).one()
    # check owner of item before deleting
    if itemToDelete.user_id != login_session['user_id']:
        return """<script>function myFunction() {alert(
               'You are not authorized to delete this item.');}
               </script><body onload='myFunction()'>"""
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash("Item is deleted!")
        return redirect(url_for('showAllItems', category_name=category_name))
    else:
        return render_template('deleteItem.html', item=itemToDelete)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000, threaded=False)
