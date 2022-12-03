require("dotenv").config()
const app=require("./app")
const port=process.env.PORT

app.listen(port || 5000,()=>{
    console.log(`server is running at http://localhost:${port}`)
})