require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const req = require('express')
const morgan = require('morgan');

const app = express()

if (process.env.NODE_ENV === 'development') {
    app.use(morgan('dev'));
}

//Configure json response
app.use(express.json())

//Models
const User = require('./model/User')
const Note = require('./model/Note')

//Public Route
app.get('/', (req, res) => {
    res.status(200).json({ msg: "Bem vindo a minha api" })
})

app.post('/notes/save', checkToken, async (req, res) => {
    const { title, description, created, modified } = req.body

    if (!title) {
        return res.status(422).json({ msg: 'O título é obrigatório' })
    }

    const note = new Note({
        title,
        description,
        created,
        modified
    })

    try {

        await note.save()

        res.status(201).json({ msg: 'Nota adicionada com sucesso' })

    } catch (error) {
        console.log(error)
        res.status(500).json({ msg: 'Aconteceu um erro no servidor, tente novamente' })
    }


})

app.get('/notes', checkToken, async (req, res) => {

    try {
        const listOfNotes = await Note.find()
        res.status(200).json({ listOfNotes })
    } catch (error) {
        console.log(error)
        res.status(500).json({ msg: 'Algo errado aconteceu com o Servidor, tente novamente mais tarde' })
    }
    
})

//Private route
app.get('/user/:id', checkToken, async (req, res) => {

    const id = req.params.id

    const user = await User.findById(id, '-password')

    if (!user) {
        return res.status(404).json({ msg: 'Usuário não encontrado' })
    }

    res.status(200).json({ user })
})

//Register User
app.post('/auth/register', async (req, res) => {

    const { name, email, password, confirmPassword } = req.body

    //validations
    if (!name) {
        return res.status(422).json({ msg: 'O nome é obrigatório!' })
    }
    if (!email) {
        return res.status(422).json({ msg: 'O email é obrigatório!' })
    }
    if (!password) {
        return res.status(422).json({ msg: 'A senha é obrigatória!' })
    }
    if (password !== confirmPassword) {
        return res.status(422).json({ msg: 'As senhas não conferem!' })
    }

    //check user if exists
    const userExists = await User.findOne({ email: email })

    if (userExists) {
        return res.status(422).json({ msg: 'Por favor, utilize outro e-mail!' })
    }

    //create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    //create user
    const user = new User({
        name,
        email,
        password: passwordHash
    })

    try {

        await user.save()

        res.status(201).json({ msg: 'Usuário criado com sucesso' })


    } catch (error) {
        console.log(error)
        res.status(500).json({ msg: 'Aconteceu um erro no servidor, tente novamente' })
    }

})

app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body

    //validations
    if (!email) {
        return res.status(422).json({ msg: 'O email é obrigatório!' })
    }
    if (!password) {
        return res.status(422).json({ msg: 'A senha é obrigatória!' })
    }

    //check user if exists
    const user = await User.findOne({ email: email })

    if (!user) {
        return res.status(422).json({ msg: 'Usuário não encontrado no sistema' })
    }
    //check is password match
    const checkPassword = await bcrypt.compare(password, user.password)

    if (!checkPassword) {
        return res.status(422).json({ msg: 'Senha inválida' })
    }

    try {

        const secret = process.env.SECRET

        const token = jwt.sign(
            {
                id: user._id
            },
            secret
        )

        res.status(200).json({ msg: 'Autenticação realizada com sucesso', token })

    } catch (error) {
        console.log(error)
        res.status(500).json({ msg: 'Aconteceu um erro no servidor, tente novamente' })
    }


})

function checkToken(req, res, next) {

    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (!token) {
        return res.status(401).json({ msg: 'Acesso Negado!' })
    }

    try {

        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()

    } catch (error) {
        res.status(400).json({ msg: 'Token Inválido!' })
    }
}


const PORT = process.env.PORT || 5000

//Credentials
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS
const dbName = process.env.DB_NAME

//Database Connection
mongoose.connect(
    `mongodb+srv://${dbUser}:${dbPassword}@${dbName}.jntdb.mongodb.net/?retryWrites=true&w=majority`
).then(() => {
    app.listen(PORT, console.log(`Server Running in ${process.env.NODE_ENV} mode on port ${PORT}`))
    console.log("Connected to database")
}).catch((err) => console.log(err))

