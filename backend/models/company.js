const mongoose = require('mongoose')
const {Schema} = mongoose

const companySchema = new Schema({
    passwordTables: {
        type: Array,
        default: []
    },
    Authenticated: {
        type: Array,
        default: []
    }
})

module.exports = mongoose.model('Company', companySchema)