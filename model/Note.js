const mongoose = require('mongoose')

const Note = mongoose.model('Note' , {
    title: String,
    description: String,
    created: String,
    modified: String
})

module.exports = Note