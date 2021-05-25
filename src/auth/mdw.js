const { verifyAccessToken } = require("./index")
const UserModel = require("../users/schema")

const authorize = async (req, res, next) => {
  try {
    //const token = req.header("Authorization").replace("Bearer ", "")

    const token = req.cookies.accessToken
    const decoded = await verifyAccessToken(token)
    const user = await UserModel.findOne({ _id: decoded._id })
    if (!user) throw new Error()
    req.user = user
    req.token = token
    next()
  } catch (error) {
    console.log(error)
    const err = new Error("Authenticate")
    err.httpStatusCode = 401
    next(err)
  }
}

module.exports = { authorize }