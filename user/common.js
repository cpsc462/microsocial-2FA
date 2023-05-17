const axios = require('axios')
const { getReasonPhrase } = require('http-status-codes')

const { paths } = require('./unprotectedPaths')

const USERS_SERVICE_NAME = 'Users'
const CONTENT_SERVICE_NAME = 'Content'
const RELATIONSHIPS_SERVICE_NAME = 'Relationships'
const MESSAGES_SERVICE_NAME = 'Messages'
const NOTIFICATIONS_SERVICE_NAME = 'Notifications'
const ANALYTICS_SERVICE_NAME = 'Analytics'

const Services = {}
Services[USERS_SERVICE_NAME] = { port: 8000 }
Services[CONTENT_SERVICE_NAME] = { port: 8001 }
Services[RELATIONSHIPS_SERVICE_NAME] = { port: 8002 }
Services[MESSAGES_SERVICE_NAME] = { port: 8003 }
Services[NOTIFICATIONS_SERVICE_NAME] = { port: 8004 }
Services[ANALYTICS_SERVICE_NAME] = { port: 8005 }

/*
 * @function uri
 * Produce the URL/URI for a service
 * @param {string} [path=""] - If empty, returns the service URL
 * @param {string} [typ=(My Service)] - one of the service types, defaults to MY_SERVICE
 * @returns {string} a FQDN with no path, or with a path
 */
function uri(typ, path) {
  const current_host = 'localhost'
  const default_scheme = 'http'

  if (!(typ in Services)) {
    throw new Error(`Service type '${typ}' not known.`)
  }
  host = Services[typ].host || current_host
  port = Services[typ].port
  scheme = Services[typ].scheme || default_scheme

  if (path === undefined) {
    path = ''
  }

  return `${scheme}://${host}:${port}${path}`
}
const unprotectedPaths = () => {
  const usablePaths = []
  paths.forEach((spec) => {
    if ('exact' in spec) {
      usablePaths.push(spec.exact)
    }
    if ('regex' in spec) {
      usablePaths.push(new RegExp(spec.regex))
    }
    if ('head' in spec) {
      usablePaths.push(new RegExp(`^${spec.head}/`))
    }
  })
  if (paths.length != usablePaths.length || paths.length == 0) {
    console.log(
      'Unexpected: expected unprotected paths; found 0 or wrong number'
    )
  }
  return usablePaths
}

function log_event(eventBody) {
  axios
    .post(uri(ANALYTICS_SERVICE_NAME, '/events'), eventBody)
    .catch(function (error) {
      console.error({
        message: `Event Logging failed. Was logging ${eventBody.type}`,
        error: error.message.split('\n')[0]
      })
    })
}

// returns false as a signal to any following code that "we're done"
function returnError(res, event) {
  statusCode = event.status
  statusMessage =
    'statusMessage' in event ? event.statusMessage : getReasonPhrase(statusCode)

  log_event(event)
  console.log(event)

  if ( 'headers' in event) {
    event.headers.keys().forEach( kk => {
      res.set(kk, event.headers[kk])
    })
  }
  res.statusMessage = statusMessage
  res.status(statusCode).end()
  return false
}

// create a function that applies any "missing" params
function curry(func) {
  return function curried(...args) {
    if (args.length >= func.length) {
      return func.apply(this, args)
    } else {
      return function (...args2) {
        return curried.apply(this, args.concat(args2))
      }
    }
  }
}

// creates a function that strips off params, i.e. the service name
var curried_uri = curry(uri)

module.exports.curry = curry
module.exports.log_event = log_event
module.exports.returnError = returnError

module.exports.Services = Services
module.exports.uri = uri
module.exports.unprotectedPaths = unprotectedPaths

module.exports.USERS_SERVICE_NAME = USERS_SERVICE_NAME
module.exports.CONTENT_SERVICE_NAME = CONTENT_SERVICE_NAME
module.exports.RELATIONSHIPS_SERVICE_NAME = RELATIONSHIPS_SERVICE_NAME
module.exports.MESSAGES_SERVICE_NAME = MESSAGES_SERVICE_NAME
module.exports.NOTIFICATIONS_SERVICE_NAME = NOTIFICATIONS_SERVICE_NAME
module.exports.ANALYTICS_SERVICE_NAME = ANALYTICS_SERVICE_NAME

module.exports.USERS_SERVICE = curried_uri(USERS_SERVICE_NAME)
module.exports.CONTENT_SERVICE = curried_uri(CONTENT_SERVICE_NAME)
module.exports.RELATIONSHIPS_SERVICE = curried_uri(RELATIONSHIPS_SERVICE_NAME)
module.exports.MESSAGES_SERVICE = curried_uri(MESSAGES_SERVICE_NAME)
module.exports.NOTIFICATIONS_SERVICE = curried_uri(NOTIFICATIONS_SERVICE_NAME)
module.exports.ANALYTICS_SERVICE = curried_uri(ANALYTICS_SERVICE_NAME)

// >>>>>>> Configure as needed
module.exports.MY_SERVICE_NAME = USERS_SERVICE_NAME
// <<<<<<<<<<<<<
module.exports.MY_SERVICE = curried_uri(USERS_SERVICE_NAME)("")
