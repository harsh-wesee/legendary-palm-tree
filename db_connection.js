const mysql = require('mysql2');

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '1234',
    database: 'chat_app'
});

// module.exports = pool.promise();


connection.connect((err) => {
    if (err)
    {
        console.error("Error connecting to the database:", err);
    }
    else
    {
        console.log("Connected to MySQL databse.");
    }
  });

module.exports = connection;