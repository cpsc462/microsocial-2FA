import { db } from '../db.js'
import Ajv, { ValidationError } from 'ajv'
import { Post, UpdatePost } from '../models/schema-validation.js'
// import axios from 'axios'

const ajv = new Ajv({ allErrors: true })
const postValidate = ajv.compile(Post)
const updatePostValidate = ajv.compile(UpdatePost)

export const getAllPosts = async (req, res) => {
  const page = parseInt(req.query.page) || 1
  const pageSize = 10
  const offset = (page - 1) * pageSize

  const q = db.prepare('SELECT * FROM posts ORDER BY date DESC LIMIT ? OFFSET ? ')
  const result = q.all(pageSize, offset)

  const count = db.prepare('SELECT COUNT(*) FROM posts').get()['COUNT(*)'];
  const noOfPages = Math.ceil(count / pageSize)

  return res.status(200).json({
    result: result,
    noOfPages: noOfPages
  })
}

export const getPostById = async (req, res) => {
  const { post_id } = req.params
  if (!post_id) return res.status(400).json({ error: 'Invalid id' })

  const q = db.prepare('SELECT * FROM posts WHERE id=?')
  const result = q.get(post_id)

  if (result) return res.status(200).json({ result: result })
  else return res.status(404).json({ error: 'Item not found' })
}

export const getPostByUsername = async (req, res) => {
  const { username } = req.params

  if (!username) return res.status(400).json({ error: 'Invalid Id' })

  const q = db.prepare('SELECT * FROM posts WHERE username=?')
  const result = q.all(username)
  if (result) return res.status(200).json({ result: result })
  else return res.status(404).json({ error: 'Item not found' })
}

export const createPost = async (req, res) => {
  if (!postValidate(req.body)) {
    const error = new ValidationError(postValidate.errors)
    return res.status(400).json({ error })
  }
  const { username, title, description } = req.body
  const tags = req.body.tags || null
  const image = req.body.image || null
  const currentDate = new Date()

  // Insert to database
  const q = db.prepare(
    'INSERT INTO posts (username, title, date, tags, image, description) VALUES (?, ?, ?, ?, ?, ?)'
  )
  const result = q.run(
    username,
    title,
    currentDate.toISOString(),
    tags,
    image,
    description
  )

  return res.status(201).json({
    message: 'success',
    data: {
      id: result.lastInsertRowid,
      date: currentDate.toISOString(),
      description: description,
      image: image,
      tags: tags,
      title: title,
      username: username
    }
  })
}

export const deletePostById = async (req, res) => {
  const { post_id } = req.params
  if (!post_id) return res.status(400).json({ error: 'Invalid input data' })

  const q = db.prepare(`DELETE FROM posts WHERE id=?;`)
  const result = q.run(post_id).changes
  if (result > 0) return res.status(204).json({ message: 'success' })
  else return res.status(404).json({ error: 'Id not found' })
}

export const updatePostById = async (req, res) => {
  if (!updatePostValidate(req.body)) {
    const error = new ValidationError(updatePostValidate.errors)
    return res.status(400).json({ error })
  }
  const { post_id, title, tags, image, description } = req.body
  const q = db.prepare(
    `UPDATE posts SET title=?, tags=?, image=?, description=? WHERE id=?`
  )
  const result = q.run(title, tags, image, description, post_id).changes
  if (result > 0) res.status(204).json({ message: 'success' })
  else res.status(404).json({ error: 'Id not found' })
}
