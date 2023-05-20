const {
  ReasonPhrases,
  StatusCodes,
  getReasonPhrase,
  getStatusCode
} = require('http-status-codes')
var express = require('express')
var ms = require('ms')
const { v4: uuidv4 } = require('uuid')

var router = express.Router()
module.exports.router = router

const { USERS_SERVICE, log_event, returnError } = require('../common')
const { db } = require('../db')
const { validate } = require('../utils/schema-validation')
const { regexpCode } = require('ajv/dist/compile/codegen')

// convert what they type in the "sort=" to an appropriate column name
function colspec_to_orderby (spec) {
  // not worried about match failing because we've already validated this
  match = spec.match(/^(\w+)([+-]?)$/)
  column_name = match[1]
  clause = column_name
  if (match[2] === '-') {
    clause += ' DESC'
  }
  return clause
}

function deleteExpiredResultSets () {
  expired_results_as_of = new Date()
  expired_results_as_of.setSeconds(
    expired_results_as_of.getSeconds() -
      ms(process.env.CURSOR_EXPIRATION) / 1000
  )
  const expire_stmt = db.prepare(
    'DELETE FROM users_result_sets WHERE set_results_as_of < ?'
  )
  expire_stmt.run(expired_results_as_of.toISOString())
}

function deleteResultSetsBySessionId (session_id) {
  const del_stmt = db.prepare(
    'DELETE FROM users_result_sets WHERE set_session_id = ?'
  )
  del_stmt.run(session_id)
  return true
}

// all the terms we might see in a URL
const terms = [
  { term: 'start_at', type: 'int' },
  { term: 'page_size', type: 'int' },
  { term: 'id_GE', clause: 'id >= ?', type: 'int' },
  { term: 'id_GT', clause: 'id > ?', type: 'int' },
  { term: 'id', clause: 'id = ?', type: 'int' },
  { term: 'id_EQ', clause: 'id = ?', type: 'int' },
  { term: 'id_NE', clause: 'id != ?', type: 'int', inverted: true },
  { term: 'id_LE', clause: 'id <= ?', type: 'int' },
  { term: 'id_LT', clause: 'id < ?', type: 'int' },
  { term: 'name_GE', clause: 'name >= ?' },
  { term: 'name_GT', clause: 'name > ?' },
  { term: 'name_NE', clause: 'name != ?', inverted: true },
  { term: 'name', clause: 'name = ?', inverted: false },
  { term: 'name_EQ', clause: 'name = ?', inverted: false },
  { term: 'name_LE', clause: 'name <= ?' },
  { term: 'name_LT', clause: 'name < ?' }
]

// Which of all the *query* (where-clause) terms are present?
function any_term_in_request (req, terms) {
  result = terms.every((t) => {
    if (t.term in req.query && 'clause' in t) {
      return false
    }
    return true
  })
  return !result
}

function partial_range_requested(req) {
  if ('page_size' in req.query || 'start_at' in req.query || 'end_at' in req.query) {
    return true
  }
  return false
}

function row_count_for_session(session_id) {
  const row_count_map = db.get(
    'SELECT COUNT(*) AS row_count FROM users_result_sets WHERE set_session_id = ?',
    [session_id]
  )
  return row_count_map.row_count
}

// anything other than start_at/page_size means new query
function should_create_new_result_set (req, session_id) {
  row_count = row_count_for_session(session_id)
  if ( !row_count) {
    return true
  }

  return any_term_in_request(req, terms) || 'sort' in req.query
}

// req.query comes in as strings. but we need them to BE integers to validate
function to_int (x) {
  as_int = parseInt(x)
  if (as_int === NaN) {
    return x
  }
  return as_int
}

function sort_clause_SQL (req) {
  if (!('sort' in req.query)) {
    return 'id'
  }

  options = req.query.sort.split(',')

  sort_clause = options.map((x) => colspec_to_orderby(x)).join(',')

  return sort_clause
}

// do we have a session id? if so return it. otherwise create one
function query_session_id (req) {
  const authenticated = req.auth !== undefined && 'session' in req.auth
  session_id = uuidv4()
  if ('session' in req.query) {
    session_id = req.query.session  }
  if (authenticated) {
    session_id = req.auth.session
  }
  return session_id
}

function where_clause_from_query (req) {
  where_clauses = []
  where_vals = []
  terms
    .filter((x) => 'clause' in x)
    .forEach((x) => {
      const { term, clause, inverted } = x
      if (term in req.query) {
        if (Array.isArray(req.query[term])) {
          const conjunction = inverted ? ' AND ' : ' OR '
          clauses =
            '(' +
            Array(req.query[term].length).fill(clause).join(conjunction) +
            ')'
          // console.log({in: "where_clause_from_query", term:clauses,vals:req.query[term]})
          where_clauses.push(clauses)
          where_vals = where_vals.concat(req.query[term])
        } else {
          // console.log({in: "where_clause_from_query", term:clause,val:req.query[term]})
          where_clauses.push(clause)
          where_vals.push(req.query[term])
        }
      }
    })

  where_clause = where_clauses.join(' AND ')
  if (where_clause !== '') {
    where_clause = ' WHERE ' + where_clause
  }
  return [where_clause, where_vals]
}

// populate a users_results_set for this session id
function create_new_result_set (req, session_id) {
  now = new Date().toISOString()

  const [where_clause, where_vals] = where_clause_from_query(req)

  // hardcoding user_id for now
  all_where_vals = [1, now, session_id, ...where_vals]

  const sort_clause = sort_clause_SQL(req)
  const result_sql =
    `INSERT INTO users_result_sets ` +
    `(set_querying_user_id, set_results_as_of, set_session_id, ` +
    `set_rownum, ` +
    `id, name, versionkey) ` +
    `SELECT ` +
    `?,?,?,` +
    `ROW_NUMBER() OVER (ORDER BY ${sort_clause}),` +
    `id,name,versionkey ` +
    `FROM ` +
    `users` +
    where_clause

  console.log({ in: create_new_result_set, result_sql, all_where_vals, queryparams: req.query, sort_clause })
  const result_set_stmt = db.prepare(result_sql)

  // creates result rows
  result_set_stmt.run(all_where_vals)
  return true
}

// returns [{start: end:}...] ranges (either start or end may be NaN/undefined),
// or false when the range is not valid
function ranges_from_header_string (hdr) {
  // should validate...

  range_header_parts = hdr.match(/^(\w+)\s*=\s*(.+)$/)
  unit_type = range_header_parts[1]

  if (unit_type !== 'rows') {
    // logReturn!
    return false
  }

  specs = range_header_parts[2]
  range_specs = specs.split(/\s*,\s*/)
  // if no commas, split does not return an array -- just a string
  if (typeof range_specs == 'string') {
    range_specs = [range_specs]
  }

  ranges = []
  succeeded = range_specs.every((range) => {
    const match = range.match(/(\d+)-(\d*)|-(\d+)/)
    if (typeof match != 'object') {
      // error - no match
      return false
    }
    //ignore "complete string" (first array elem from .match)
    match.shift()

    const [first_num, second_num, alternate_second] = match

    start = undefined
    end = undefined
    if (first_num != '') {
      start = parseInt(first_num)
    }
    if (second_num != '' || alternate_second != '') {
      end = parseInt(second_num != '' ? second_num : alternate_second)
    }
    ranges.push({ start, end })
    return true
  })

  // console.log({ in:"ranges_from_header_string", hdr, unit_type, range_header_parts, specs, ranges })

  if (!succeeded) {
    console.log('ranges_from_header_string failed!')
    return false
  }

  return ranges
}

function range_from_query_params (start, end) {
  // query params...

  // if neither are defined coming in, call it valid
  if (start === undefined && start === undefined) {
    return [{ start, end }]
  }

  // could validate this (but let's let swagger do that)
  if (start !== undefined) {
    start = parseInt(start)
    // return false if NaN?
  }
  if (end !== undefined) {
    end = parseInt(end)
    // return false if NaN?
  }

  // both missing = not a range because parseInt failed
  if (start === undefined && start === undefined) {
    return []
  }
  return [{ start, end }]
}

function identify_requested_row_ranges (req, res) {
  // header trumps query vals
  range_header = req.get('Range')
  if (typeof range_header == 'string') {
    return ranges_from_header_string(range_header)
  }

  return range_from_query_params(
    req.query['start_at'],
    req.query['end_at']
  )
}

function populate_unspecified_range_values (ranges, row_count) {
  // convert and undefined start/end to correct values
  return ranges.map((rr) => {
    if (isNaN(rr.start)) {
      rr.start = 0
    }
    if (isNaN(rr.end)) {
      rr.end = row_count - 1
    }
    return { start: rr.start, end: rr.end }
  })
}

function is_full_range (ranges, row_count) {
  return (
    ranges.length == 1 && ranges[0].start == 0 && ranges[0].end == row_count - 1
  )
}

function respond_directly_with_query (req, res) {
  const [where_clause, where_vals] = where_clause_from_query(req)

  const sort_clause = sort_clause_SQL(req)
  const get_users_sql =
    `SELECT ` +
    `id,name,versionkey ` +
    `FROM ` +
    `users` +
    where_clause +
    ` ORDER BY ${sort_clause}`

  console.log({ in:"respond_directly_with_query",
    get_users_sql,
    where_vals,
    queryparams: req.query,
    sort_clause
  })
  const get_users_stmt = db.prepare(get_users_sql)

  // creates result rows
  users = get_users_stmt.all(where_vals)
  row_count = users.length

  // post-process users...
  users.forEach((user) => {
    user.uri = USERS_SERVICE(`/user/${user.id}`)
  })

  const response = {
    users: users,
    row_count
  }

  res.set('Content-Range', `rows 0-${row_count - 1}/${row_count}`)
  res.set('Accept-Ranges', 'rows')
  res.status(StatusCodes.OK)
  res.json(response)
}

// once the result set is populated, we return out of that (not doing the query again)
function respond_from_existing_result_set (req, res, session_id) {
  // make sure this is present and accurate -- not gonna trust what they passed in
  const row_count = row_count_for_session(session_id)

  requested_ranges = identify_requested_row_ranges(req, res)
  if (requested_ranges === false) {
      return returnError(res, {
        status: StatusCodes.REQUESTED_RANGE_NOT_SATISFIABLE,
        severity: 'Medium',
        type: 'BadRange',
        message: `Invalid Range header received`,
        headers: [ { 'Content-Range': `rows */${row_count}`}]
      })
  }

  requested_ranges = populate_unspecified_range_values(
    requested_ranges,
    row_count
  )

  //console.log({ requested_ranges })

  // pull from results, not fresh query
  const get_users_from_set = `SELECT id, name, versionkey, set_rownum FROM users_result_sets WHERE set_session_id = ? ORDER BY set_rownum LIMIT ? OFFSET ?`
  const get_users_from_set_stmt = db.prepare(get_users_from_set)

  users = []

  page_size = undefined
  if (req.query['page_size'] !== undefined) {
    page_size = req.query['page_size']
  }

  range_sets = []
  requested_ranges.every((range) => {
    row_limit = range.end - range.start + 1
    if (page_size !== undefined && row_limit > page_size) {
      row_limit = page_size
    }
    some_users = get_users_from_set_stmt.all(session_id, row_limit, range.start)
    users = users.concat(some_users)

    range_sets.push(`${range.start}-${range.start + row_limit - 1}`)

    if (page_size !== undefined) {
      page_size -= some_users.length
      if (page_size == 0) {
        // stop when we've found enough rows
        return false
      }
    }
    return true
  })

  // post-process users...
  users.forEach((user) => {
    user.uri = USERS_SERVICE(`/user/${user.id}`)

    // we needed this row to make order by/limit/offset work correctly. but do not show user.
    delete user.set_rownum
  })

  // puzzle - what should we send for range if multiple ranges?
  const response = {
    users: users,
    row_count
  }

  // we don't add the session id to the results if it is stored in the auth token
  const authenticated = req.auth !== undefined && 'session' in req.auth
  if (!authenticated) {
    response.session = session_id
  }

  res.set('Content-Range', `rows ${range_sets}/${row_count}`)
  res.set('Accept-Ranges', 'rows')

  res.status(StatusCodes.OK)
  // Entire range? it's a 200. Otherwise partial range
  if (page_size !== undefined || !is_full_range(requested_ranges, row_count)) {
    res.status(StatusCodes.PARTIAL_CONTENT)
    //return
  }
  res.json(response)
}

function adjust_params_for_validation (req) {
  // have to do this (rewrite strings to ints) to enable validation of integers
  terms
    .filter((x) => 'type' in x && x.type === 'int')
    .map((x) => x.term)
    .filter((x) => x in req.query)
    .forEach((x) => {
      if (Array.isArray(req.query[x])) {
        req.query[x] = req.query[x].map((y) => to_int(y))
      } else {
        req.query[x] = to_int(req.query[x])
      }
    })
}

function are_params_valid (req, res) {
  // extend filteringspec to disallow arrays for <things>
  // include session id if it's in the query
  errors = validate.UserFilteringSpec(req.query, '{query param}')
  if (errors.length) {
    res.json(errors)
    res.statusMessage = 'Invalid data'
    res.status(StatusCodes.UNPROCESSABLE_ENTITY).end()
    return false
  }

  if ('sort' in req.query && req.query.sort.length > 0) {
    options = req.query.sort.split(',')
    errors = validate.UserSortingSpec(options, '{sort param}')
    if (errors.length) {
      res.json(errors)
      res.statusMessage = 'Invalid data'
      res.status(StatusCodes.UNPROCESSABLE_ENTITY).end()
      return false
    }
  }
  return true
}

/**
 * @swagger
 * /users:
 *   get:
 *     summary: Retrieve Users
 *     description: Retrieve Users, optionally filtering by query params
 *     operationId: GetUsers
 *     tags: [Users API]
 *     responses:
 *       200:
 *         description: Success - 0 or more Users returned
 *         content:
 *           application/json:
 *             schema:
 *                type: array
 *                items:
 *                   $ref: '#/components/schemas/RetrievedUser'
 *       400:
 *         description: Invalid Query
 */
router.get('/users', async (req, res) => {
  // FIXME: arguably we should just do this perodically, but this is easier for now
  deleteExpiredResultSets()

  adjust_params_for_validation(req)
  if (!are_params_valid(req, res)) {
    return
  }

  if (partial_range_requested(req)) {
    session_id = query_session_id(req)

    if (should_create_new_result_set(req,session_id)) {
      if (!deleteResultSetsBySessionId(session_id)) {
        return
      }
      if (!create_new_result_set(req, session_id)) {
        return
      }
    }
    return respond_from_existing_result_set(req, res, session_id)
  }
  return respond_directly_with_query(req, res)
})

/**
 * @swagger
 * /users:
 *   post:
 *     summary: Create User
 *     description: Create a new User
 *     operationId: CreateUser
 *     tags: [Users API]
 *     requestBody:
 *       required: true
 *       content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/CreatingUser'
 *     responses:
 *       201:
 *         description: User Created
 *         content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/RetrievedUser'
 *         links:
 *            'Retrieving Users':
 *              operationId: GetUserById
 *              parameters:
 *                id: '$response.body#/id'
 *              description: >
 *                The `id` value returned in the response can be used as
 *                the `id` parameter in `GET /user/{id}`.
 *            'Updating a User':
 *              operationId: UpdateUserById
 *              parameters:
 *                id: '$response.body#/id'
 *              description: >
 *                The `id` value returned in the response can be used as
 *                the `id` parameter in `PUT /user/{id}`.
 *            'Deleting a User':
 *              operationId: DeleteUserById
 *              parameters:
 *                id: '$response.body#/id'
 *              description: >
 *                The `id` value returned in the response can be used as
 *                the `id` parameter in `DEL /user/{id}`.
 *       400:
 *          description: User data is not acceptable
 *          examples: [ "Invalid user name",
 *                "Invalid password",
 *                "User with that name already exists" ]
 */
router.post('/users', (req, res) => {
  user = req.body

  // XML adds an outer wrapper
  while ( 'user' in user ) {
    user = user.user;
  }

  errors = validate.CreatingUser(user, '{body}')
  if (errors.length) {
    log_event({
      severity: 'Low',
      type: 'CreateUserFailed',
      message: `User Creation failed: ${JSON.stringify(errors)}`
    })
    res.json(errors)
    res.statusMessage = 'Invalid data'
    res.status(StatusCodes.UNPROCESSABLE_ENTITY).end()
    return
  }

  const stmt = db.prepare(`INSERT INTO users (name, password)
                 VALUES (?, ?)`)

  try {
    info = stmt.run([user.name, user.password])
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      log_event({
        severity: 'Low',
        type: 'NonUniqueNameCreateRequest',
        message: `Create Request for (existing) User ${user.name} received.`
      })

      res.statusMessage = 'Account already exists'
      res.status(StatusCodes.BAD_REQUEST).end()
      return
    }
    log_event({
      severity: 'Low',
      type: 'CannotCreateUser',
      message: `Create ${[ser.name, user.password]} failed: ${err}`
    })
    console.log('insert error: ', { err, info, user })
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).end()
    return
  }

  // we're just returning what they submitted. but we never return the password
  user.id = info.lastInsertRowid
  user.uri = USERS_SERVICE(`/user/${user.id}`)
  delete user.password

  log_event({
    severity: 'Low',
    type: 'UserCreated',
    message: `User ${user.id} (name ${user.name}) created.`
  })

  res.set('Location', user.uri)
  res.type('json')
  res.json(user)
  res.status(StatusCodes.CREATED)
})
