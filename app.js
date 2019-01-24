'use strict';

// load modules
const express = require('express');
const morgan = require('morgan');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const auth = require('basic-auth');

// load mongoose models
const User = require('./models').User;
const Course = require('./models').Course;

// variable to enable global error logging
const enableGlobalErrorLogging = process.env.ENABLE_GLOBAL_ERROR_LOGGING === 'true';

// create the Express app
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// connect to the database and save the connection
mongoose.connect('mongodb://localhost/fsjstd-restapi');
const db = mongoose.connection;

// handle mongoose connection events
db.once('open', () => console.log('Successfully connected to the "fsjstd-restapi" database'));
db.on('error', error => console.log('Cannot connect to the database! Error: ' + error));

// setup morgan which gives us http request logging
app.use(morgan('dev'));

function createAndThrowError(message, statusCode, next) {
  const error = new Error(message);
  error.status = statusCode || 500;
  next(error);
}

// user authorization
const authorization = (req, res, next) => {
  const userAuth = auth(req);

  if (userAuth) {
    User.findOne({emailAddress: userAuth.name}).exec()
      .then(user => {
        if (user) {
          bcrypt.compare(userAuth.pass, user.password, (error, result) => {
            if (error) {
              createAndThrowError(error.message, 500, next);
            }

            if (result) {
              req.user = user;
              next();
            } else {
              createAndThrowError('Password is incorrect!', 401, next);
            }
          });
        } else {
          createAndThrowError('User is not found!', 401, next);
        }
      })
      .catch(error => {
        createAndThrowError(error.message, 401, next);
      });
  } else {
    createAndThrowError('Authorization headers are invalid!', 401, next);
  }
};

// TODO setup your api routes here

// Get authorized user
app.get('/api/users', authorization, (req, res, next) => {
  res.status(200).json(req.user);
});

// Create new user
app.post('/api/users', (req, res, next) => {
  const emailRegex = /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/gi;
  // test if email is valid
  if (emailRegex.test(req.body.emailAddress)) {
    // Check for existing email address
    User.findOne({emailAddress: req.body.emailAddress}).exec()
    .then(user => {
      if (!user) {
        const password = req.body.password;
        // chech if password is not empty before hashing
        if (password && password.length > 0) {
          bcrypt.hash(password, 10) // hash password and create new user
          .then(hash => {
            const user = new User({
              firstName: req.body.firstName,
              lastName: req.body.lastName,
              emailAddress: req.body.emailAddress,
              password: hash
            });
          
            user.save()
              .then(user => {
                res.location('/');
                res.status(201).end();
              })
              .catch(error => {
                error.statusCode = 400;
                next(error);
              });
          })
          .catch(error => {
            createAndThrowError(error.message, 500, next);
          });
        } else {
          let errorMessage;
          if (!password) {
            errorMessage = 'Password path is required!';
          } else if (password.length === 0) {
            errorMessage = 'Password path cannot be empty!';
          }

          // if password is empty
          createAndThrowError(errorMessage, 401, next);
        }
      } else {
        createAndThrowError('User email already exists!', 401, next);
      }
    })
    .catch(error => createAndThrowError(error.message, 401, next));
  } else {
    createAndThrowError('The email is not valid!', 401, next);
  }
});

// get all courses populated with users that own each course
app.get('/api/courses', (req, res, next) => {
  Course.find().populate('user', 'firstName lastName').exec()
    .then(courses => {
      res.status(200).json({
        courseCount: courses.length,
        courses
      });
    })
    .catch(error => {
      createAndThrowError(error.message, 500, next);
    })
});

// get course with provided id and populate it with user who owns it
app.get('/api/courses/:id', (req, res, next) => {
  Course.findById(req.params.id).populate('user', 'firstName lastName').exec()
    .then(course => {
      if (course) {
        res.status(200).json({
          course
        });
      } else {
        createAndThrowError(`The course with id ${req.params.id} is not found!`, 401, next);
      }
    })
    .catch(error => {});
});

// create new course
app.post('/api/courses', authorization, (req, res, next) => {
  const course = new Course({
    user: req.user._id,
    title: req.body.title,
    description: req.body.description,
    estimatedTime: req.body.estimatedTime,
    materialsNeeded: req.body.materialsNeeded
  });

  course.save()
    .then(course => {
      res.location('/');
      res.status(201).end();
    })
    .catch(error => createAndThrowError(error.message, 400, next));
});

// update course
app.put('/api/courses/:id', authorization, (req, res, next) => {
  Course.findById(req.params.id).exec()
    .then(course => {
      if (course.user.toString() === req.user._id.toString()) {
        const updatedDocument = {
          user: req.user._id,
          title: req.body.title,
          description: req.body.description,
          estimatedTime: req.body.estimatedTime,
          materialsNeeded: req.body.materialsNeeded
        };
      
        Course.updateOne({_id: req.params.id}, updatedDocument, {runValidators: true}, (error, course) => {
          if (error) {
            createAndThrowError(error.message, 500, next);
          }
      
          res.status(204).end();
        });
      } else {
        createAndThrowError('Currently authorized user cannot make changes to this course!', 403, next);
      }
    })
    .catch(error => createAndThrowError(error.message, 500, next));
});

// delete course 
app.delete('/api/courses/:id', authorization, (req, res, next) => {
  Course.findById(req.params.id).exec()
    .then(course => {
      if (course.user.toString() === req.user._id.toString()) {
        Course.deleteOne({_id: req.params.id}, err => {
          if (err) {
            createAndThrowError(err.message, 500, next);
          }

          res.status(204).end();
        });
      } else {
        createAndThrowError('Currently authorized user cannot make changes to this course!', 403, next);
      }
    })
    .catch(error => createAndThrowError(error.message, 500, next));
});

// setup a friendly greeting for the root route
app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to the REST API project!',
  });
});

// send 404 if no other route matched
app.use((req, res) => {
  res.status(404).json({
    message: 'Route Not Found',
  });
});

// setup a global error handler
app.use((err, req, res, next) => {
  if (enableGlobalErrorLogging) {
    console.error(`Global error handler: ${JSON.stringify(err.stack)}`);
  }

  res.status(err.status || 500).json({
    message: err.message,
    error: err,
  });
});

// set our port
app.set('port', process.env.PORT || 5000);

// start listening on our port
const server = app.listen(app.get('port'), () => {
  console.log(`Express server is listening on port ${server.address().port}`);
});
