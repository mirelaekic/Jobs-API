const jwt = require("jsonwebtoken")
const UserModel = require("../users/schema")

const authenticate = async user => {
  try {
    // create tokens
    const accessToken = await generateAccessToken({ _id: user._id })
    const refreshToken = await generateRefreshToken({ _id: user._id })

    // save new refresh token in db

    user.refreshTokens = user.refreshTokens.concat({ token: refreshToken })
    await user.save()

    // return them
    return { accessToken, refreshToken }
  } catch (error) {
    console.log(error)
    throw new Error(error)
  }
}

const generateAccessToken = payload =>
  new Promise((res, rej) =>
    jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: "15m" },
      (err, token) => {
        if (err) rej(err)
        res(token)
      }
    )
  )

const verifyAccessToken = token =>
  new Promise((res, rej) =>
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) rej(err)
      res(decoded)
    })
  )

const generateRefreshToken = payload =>
  new Promise((res, rej) =>
    jwt.sign(
      payload,
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: "1 week" },
      (err, token) => {
        if (err) rej(err)
        res(token)
      }
    )
  )

const verifyRefreshToken = token =>
  new Promise((res, rej) =>
    jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (err, decoded) => {
      if (err) rej(err)
      res(decoded)
    })
  )

const refresh = async oldRefreshToken => {
  try {
    // Verify old refresh token
    const decoded = await verifyRefreshToken(oldRefreshToken) //  decoded._id

    // check if old refresh token is in db

    const user = await UserModel.findOne({ _id: decoded._id })

    const currentRefreshToken = user.refreshTokens.find(
      token => token.token === oldRefreshToken
    )

    if (!currentRefreshToken) {
      throw new Error("Bad refresh token provided!")
    }

    // if everything is ok I can create new access and refresh tokens

    const newAccessToken = await generateAccessToken({ _id: user._id })
    const newRefreshToken = await generateRefreshToken({ _id: user._id })

    // replace old refresh token in db with new one

    const newRefreshTokensList = user.refreshTokens
      .filter(token => token.token !== oldRefreshToken)
      .concat({ token: newRefreshToken })

    user.refreshTokens = [...newRefreshTokensList]
    await user.save()

    return { accessToken: newAccessToken, refreshToken: newRefreshToken }
  } catch (error) {
    console.log(error)
  }
}

module.exports = { authenticate, verifyAccessToken, refresh }