Installation manual

Run:

git clone https://github.com/ATer-Oganisyan/otushomework.git
cd crud 
alias k=kubectl
k apply -f ./kuber

Import Simple_CRUD.postman_collection.json into Postman.

Enjoy :)



# To build container run: 
docker build -t arsenteroganisyan/otus-session-server:v13 /Users/arsen/otus-session --no-cache --platform linux/amd64