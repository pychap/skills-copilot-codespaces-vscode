// Create web server


// Import express module
const express = require('express');
const app = express();

// Import body-parser module
const bodyParser = require('body-parser');

// Import path module
const path = require('path');

// Import mysql module
const mysql = require('mysql');

// Import session module
const session = require('express-session');

// Import express-handlebars module
const exphbs = require('express-handlebars');

// Import express-fileupload module
const fileUpload = require('express-fileupload');

// Import connect-flash module
const flash = require('connect-flash');

// Import passport module
const passport = require('passport');

// Import LocalStrategy module
const LocalStrategy = require('passport-local').Strategy;

// Import bcrypt module
const bcrypt = require('bcryptjs');

// Import moment module
const moment = require('moment');

// Import multer module
const multer = require('multer');

// Import nodemailer module
const nodemailer = require('nodemailer');

// Import fs module
const fs = require('fs');

// Import dotenv module
const dotenv = require('dotenv');

// Import jsonwebtoken module
const jwt = require('jsonwebtoken');

// Import cookie-parser module
const cookieParser = require('cookie-parser');

// Import cors module
const cors = require('cors');

// Import csrf module
const csrf = require('csurf');

// Import csrfProtection module
const csrfProtection = csrf({ cookie: true });

// Import csrfProtection module
const csrfProtection2 = csrf({ cookie: false });

// Import express-rate-limit module
const rateLimit = require('express-rate-limit');

// Import helmet module
const helmet = require('helmet');

// Import xss-clean module
const xss = require('xss-clean');

// Import hpp module
const hpp = require('hpp');

// Import express-mongo-sanitize module
const mongoSanitize = require('express-mongo-sanitize');

// Import express-mongo-sanitize module
const sanitize = require('mongo-sanitize');

// Import express-mongo-sanitize module
const sanitizeHtml = require('sanitize-html');

// Import express-mongo-sanitize module
const sanitizeBody = require('sanitize-html');

// Import express-mongo-sanitize module
const sanitizeComment = require('sanitize-html');

// Import express-mongo-sanitize module
const sanitizeEmail = require('sanitize-html');

// Import express-mongo-sanitize module
const sanitizeName = require('sanitize-html