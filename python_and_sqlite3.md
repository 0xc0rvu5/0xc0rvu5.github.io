# How I gained 80 lbs for bench-press and 100 lbs for squats in 8 months because of Python and Sqlite3

First off, I would like to begin with a little pretext. I played baseball for nearly 20 years alongside a short stint in football. Furthermore, I had injured my shoulder and eventually had shoulder surgery. Anyways, with that, I had never planned on getting my bench-press to where it is today! I hope I can continue on this venture and maybe even help someone else out who is inclined to do the same.

I was always a quick individual. I had been clocked at 4.3 seconds a few times during 40-yard dashes. Unfortunately, at the single combine I attended I managed to slip each attempt and ended up with a 4.5! That is a story for another time. Back to the story-line, in my high school years I never could manage to supersede 145 pounds. Similarly, in my college years I couldn't manage to surpass 165 pounds! Now I am happily 190 pounds with a strictly vegetarian diet. I may not be able to run at the speeds I used too, but I am content with that. Yes! I know, I could cut down to about 183 and be lean mass, but if you've ever trucked down that path you understand the tremendous amount of effort one must put in to achieve their desired results. Anyways, I accredit my vegetarian diet and the consumption of .8 grams of protein for every pound I weigh for the current body composition I am at. When I had been eating anything my heart desired I never could consume the extra protein shake or the extra daily smoothie I consume now. Without going any further into details about me I will just refer an awesome book that gave me a better understanding of the way meat is processed in the body. 
Superlife" by Darin Olien
I highly recommend this book if you are interested in living a healthier lifestyle. A bonus is the large amount of recipes, meals and much more included in the book.

Without further ado, I would like to acknowledge the warm place in my heart kept for Python and Sqlite3 for helping me on my journey! On a more serious note, I am grateful for coming to learn and understand Python for the last year and half because I enjoy everything it has to offer. Before I would be stuck debating whether or not I would sell my soul to use some workout tracker that is behind a paywall or keep my workout notes tracked on paper. I must tell you that I did not enjoy the latter. 

I had just recently moved again after I began officially tracking with Python and Sqlite3. Fortunately, my current residence also allows for enough real estate for my bed, my Marcy Pro Power Rack (something similar to https://poshmark.com/listing/Marcy-Pro-Platinum-Multi-functional-Power-Rack-and-Weight-Bench-Bar-Olympic-We-63a0e805ddab40083edecf9c?srsltid=AeTuncqKukJkp-0eDs1jB2lQXEQ1yy8DR_Ev4QtKSyjXq45HfEF9ZhHnaTg#utm_source=gdm_unpaid) and my PC and it's setup. Since I have the main necessities within near arm length I figured tracking workouts in a database wouldn't be too burdensome while exercises.

The database itself is nothing outside the norm. The columns consisting of an `id` section, `Exercise`, `SetxRep`, `Weight` and `Date`. To generate something similar using Python and Sqlite3 it would look something like this:
```python
# import module
import sqlite3
import datetime

# current date format in the case it is to be used as a value
today = datetime.datetime.today().strftime('%m-%d-%Y')

# connecting to sqlite
conn = sqlite3.connect(r'workouts.db')

# creating a cursor object using the cursor() method
cur = conn.cursor()

# create table
conn.execute("""CREATE TABLE workout(
id INTEGER PRIMARY KEY AUTOINCREMENT,
Exercise varchar(255),
SetxRep varchar(255),
Weight int,
Date text
);""")

cur.execute(f'''INSERT INTO WORKOUT (Exercise, SetxRep, Weight, Date) VALUES ("Curls","3x10",90,"{today}")''')

# commit your changes in the database
conn.commit()

# closing the connection
conn.close()

```

After executing this code you will have a database named `workouts.db` with 1 row of data within it which we executed on this line:
```python
cur.execute(f'''INSERT INTO WORKOUT (Exercise, SetxRep, Weight, Date) VALUES ("Curls","3x10",90,"{today}")''')
```

If you have the `sqlite3` binary installed on your system you can view it as such:
![image](https://0xc0rvu5.github.io/docs/assets/images/20230108193521.png)

The asterisk `*` signifies that we wish to select `all` data from within the `workout` database.

If you prefer GUI as many do then using the `sqlitebrowser` binary will accomplish the same. It will look similar to this:
![image](https://0xc0rvu5.github.io/docs/assets/images/20230108194034.png)

Just be sure to ensure to switch to the proper table, which, in this case, is `workout`.

As any trainer would assuredly say, "you must track your workouts!" Well, I am here to say I finally am the proper way. Now why is tracking them this method better? Well for starters, all your workout data is in one place. Maybe we want to see how many times within the last 6 months we completed the `Benchpress` exercise. Well, we can do that with Python this way:
```python
import sqlite3

target_exercise = 'Benchpress'

# connect to the database
conn = sqlite3.connect('databases/workout_main.db')

# create a cursor
cur = conn.cursor()

# execute the query
cur.execute(f"SELECT COUNT(*) FROM workout WHERE Exercise = '{target_exercise}'")

# fetch all rows from the query
rows = cur.fetchall()

# access the count value as an integer
count = rows[0][0]

print(f'The total number of rows for {target_exercise.lower()} is: {count}')
```

The output will look similar to:
![image](https://0xc0rvu5.github.io/docs/assets/images/20230108201614.png)

Alternatively, for short-hand you could execute it in the `sqlite3` shell like so:
![image](https://0xc0rvu5.github.io/docs/assets/images/20230108201743.png)

Maybe you have a `pandas` data-frame of your `Benchpress` exercise. In which, on a Linux system you can use the `cat` binary, and output your text file to the `wc` binary and count it by lines. Keep in mind, depending on whether or not you included the headers or the column names you may have to + or - a line.
![image](https://0xc0rvu5.github.io/docs/assets/images/20230108202254.png)

If you are on Windows:
```powershell
PS C:\Users\your_username> (Get-Content C:\Users\your_username\your_file.txt).Length
```

Here is the same file we used for the above example, but in descending order.
![image](https://0xc0rvu5.github.io/docs/assets/images/20230108202434.png)

Here is the code to accomplish this:
```python
import sqlite3
import pandas as pd

# create a SQL connection to our SQLite database
con = sqlite3.connect("databases/workout_main.db")

cur = con.cursor()

# return all results of query
df = pd.read_sql_query('SELECT * FROM workout WHERE Exercise = "Benchpress" ORDER BY id DESC, Date DESC', con)

# convert the values to strings before applying the str accessor
df = df.apply(lambda x: x.astype(str).str.center(20))

# center the column names
df.columns = df.columns.str.center(20)

# generate file
df.to_csv('Text Files/descending_benchpress.txt', sep='\t', index=False)

#df.to_csv('inputfile.csv', sep='|')

# close the connection
con.close()
```

Well what else can we do? Maybe visual aids help better for you! Let's take a graph and try to make some correlations between the amount of `Reps` and `Weight` achieved based off of the `Dates` of the exercise.
Now you may have noticed there are some occurrences that look like this:
![image](https://0xc0rvu5.github.io/docs/assets/images/20230108203830.png)
In order to overcome this we can make some changes to the database. First let's change the `SetxRep` column to `Reps` and remove the `Set` section of the content e.g. `3x`.
```python
import sqlite3

# connect to the database
conn = sqlite3.connect('databases/testing.db')

# create a cursor
cursor = conn.cursor()

# add the Reps columns
cursor.execute('ALTER TABLE WORKOUT ADD Reps INTEGER')

# update the Reps columns with the values on the `right` side of the 'x' of the SetxRep column
cursor.execute('UPDATE WORKOUT SET Reps = SUBSTR(SetxRep, INSTR(SetxRep, "x") + 1)')

# delete the SetxRep column
cursor.execute('ALTER TABLE WORKOUT DROP COLUMN SetxRep')

# commit the transaction
conn.commit()
```
Now the columns and content of the `Reps` column will look like this:
![image](https://0xc0rvu5.github.io/docs/assets/images/20230108204610.png)

Now, within the `Reps` rows, if there are angle brackets then we will select the first number within those angle brackets like so:
```python
import sqlite3

# connect to the database
conn = sqlite3.connect('databases/testing.db')

# create a cursor
cursor = conn.cursor()

# update the Reps column with the first number within the angle brackets
cursor.execute("UPDATE WORKOUT SET Reps = SUBSTR(Reps, INSTR(Reps, '(') + 1, INSTR(Reps, '/') - INSTR(Reps, '(') - 1) WHERE Reps LIKE '%(%'")

# commit the transaction
conn.commit()
```
The final product will be graph ready!
![image](https://0xc0rvu5.github.io/docs/assets/images/20230108205047.png)

Keep in mind that the previous two changes can be combined into a single Python script and it will achieve the same end result.
```python
import sqlite3

# connect to the database
conn = sqlite3.connect('databases/testing.db')

# create a cursor
cursor = conn.cursor()

# add the Sets and Reps columns
cursor.execute('ALTER TABLE WORKOUT ADD Reps INTEGER')

# update the Sets and Reps columns with the values of the SetxRep column and chose the content on the `right` side of the 'x'
cursor.execute('UPDATE WORKOUT SET Reps = SUBSTR(SetxRep, INSTR(SetxRep, "x") + 1)')

# update the Reps column with the first number within the angle brackets
cursor.execute("UPDATE WORKOUT SET Reps = SUBSTR(Reps, INSTR(Reps, '(') + 1, INSTR(Reps, '/') - INSTR(Reps, '(') - 1) WHERE Reps LIKE '%(%'")

# delete the SetxRep column
cursor.execute('ALTER TABLE WORKOUT DROP COLUMN SetxRep')

# commit the transaction
conn.commit()
```

Let's make a graph!
```python
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt

# connect to the database
conn = sqlite3.connect('databases/test.db')

# create a cursor
cur = conn.cursor()

# select the data you want to visualize
cur.execute('SELECT * FROM WORKOUT WHERE Exercise = "Benchpress"')

# fetch all the data
data = cur.fetchall()

# convert the data into a Pandas DataFrame
df = pd.DataFrame(data, columns=['id', 'Exercise', 'Weight', 'Date' , 'Reps'])

# convert the Date column to a datetime object
df['Date'] = pd.to_datetime(df['Date'])

# set the Date column as the index of the DataFrame
df.set_index('Date', inplace=True)

# create a figure and two subplots
fig, ax1 = plt.subplots()
ax2 = ax1.twinx()

# plot the Weight data on the first y-axis
ax1.plot(df.index, df['Weight'], color='blue', label='Weight', linestyle='dotted')
ax1.legend(loc=0)

# plot the Reps data on the second y-axis
ax2.plot(df.index, df['Reps'], color='red', label='Reps')
ax2.legend(loc=1)

# add a legend
plt.legend()

# add a title
plt.title('Benchpress Weight and Repetitions Over Time')

# show the plot
plt.show()
```

Voila! Now we can use this as a visual aid to help us understand methodologies or just to get a better understanding of where and when we were succeeding as well as struggling.
![image](https://0xc0rvu5.github.io/docs/assets/images/20230108205959.png)

To bring it all together, I would like to mention that years ago I had plateaued at around 175 lbs for bench-press. So, if you haven't deduced yet, before 175 pounds, the repetitions never went below 10. Regardless, the cadence that seems to be working for me has been to not increase weight until I can repeat 3 sets of 20 repetitions of whatever weight it may be. Now, if you are a seasoned gym rat you may understand gaining in certain areas can be increased by reducing reps and increasing weight as you can see towards the end of the graph. 

Now these were just two solid reasons why tracking your exercises are useful and how it has helped me tremendously. Bear in mind that just by seeing your week to week or day to day changes I firmly believe that this itself will help create better habits and reinforce the importance of consistency. 

Some final thoughts would be to ponder the question of what else could you do with this data? Well, what I plan on doing is creating a web-based GUI whether it be in Python or JavaScript I can't say yet. The criteria of the website would include keeping exercises in a database that can easily be added to and changed, a way to visualize each workout similar to before, but including all exercises with an easy to use UI, the occasional motivational quote and insightful meal options for the day. Depending on the web server hosting costs I may opt into using JavaScript since I may be getting rusty after my 100-days of JavaScript a little while back. On top of that I might get away with a free hosting site who knows.

Anyways, if you have any feedback or want to share a similar experience please feel free to drop a comment below. If you want to reach out and chat about Python, JavaScript, anything cyber or general health and wellness please do not hesitate! I love chatting with people despite me finding 100 things to do a day to keep me busy 😅. I definitely wont mind replacing my tasks with some good conversation! Until next time!
