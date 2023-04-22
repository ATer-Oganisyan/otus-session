Installation manual

Run:

git clone https://github.com/ATer-Oganisyan/otushomework.git
cd crud 
alias k=kubectl
helm repo add myZql https://charts.bitnami.com/bitnami		
helm install myzql-release myZql/mysql -f kuber/mysql/values.yml
k apply -f ./kuber/mysql/migrations/  
k apply -f ./kuber

Import Simple_CRUD.postman_collection.json into Postman.

Enjoy :)



# To build container run: 
docker build -t arsenteroganisyan/session-service:v1 /Users/arsen/otus-session --no-cache --platform linux/amd64