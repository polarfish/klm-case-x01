package com.afkl.cases.df.rest;

import com.afkl.cases.df.auth.ApiAuth;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import com.mashape.unirest.request.HttpRequest;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.Future;

import static org.springframework.web.bind.annotation.RequestMethod.GET;

@RestController
public class SimpleTravelApiController {

    private ApiAuth apiAuth;

    @Value("${simple-travel-api.url}")
    private String simpleTravelApiUrl;

    @Autowired
    public SimpleTravelApiController(ApiAuth apiAuth) {
        this.apiAuth = apiAuth;
    }

    private HttpRequest unirestGetWithToken(String url) throws UnirestException {
        return Unirest.get(url).header("Authorization", "Bearer " + apiAuth.getToken());
    }


    @RequestMapping(method = GET, value = "/airports", produces = "application/json; charset=UTF-8")
    public Callable<ResponseEntity<String>> query(@RequestParam Map<String, Object> params) throws UnirestException {
        return () -> {
            HttpRequest getRequest = unirestGetWithToken(simpleTravelApiUrl + "/airports").queryString(params);
            return new ResponseEntity<>(getRequest.asString().getBody(), HttpStatus.OK);
        };
    }

    @RequestMapping(method = GET, value = "/airports/{key}", produces = "application/json; charset=UTF-8")
    public Callable<ResponseEntity<String>> show(@RequestParam Map<String, Object> params,
                                                 @PathVariable("key") String key) throws UnirestException {
        return () -> {
            HttpRequest getRequest = unirestGetWithToken(simpleTravelApiUrl + "/airports/{key}").routeParam("key", key).queryString(params);
            return new ResponseEntity<>(getRequest.asString().getBody(), HttpStatus.OK);
        };
    }

    @RequestMapping(method = GET, value = "/fares/{origin}/{destination}", produces = "application/json; charset=UTF-8")
    public Callable<ResponseEntity<String>> calculateFare(@RequestParam Map<String, Object> params,
                                                          @PathVariable("origin") String origin,
                                                          @PathVariable("destination") String destination) {
        return () -> {
            HttpRequest faresRequest = unirestGetWithToken(simpleTravelApiUrl + "/fares/{origin}/{destination}")
                    .routeParam("origin", origin)
                    .routeParam("destination", destination)
                    .queryString(params);
            Future<HttpResponse<JsonNode>> faresResponseFuture = faresRequest.asJsonAsync();

            HttpRequest originRequest = unirestGetWithToken(simpleTravelApiUrl + "/airports/{key}")
                    .routeParam("key", origin).queryString(params);
            Future<HttpResponse<JsonNode>> originResponseFuture = originRequest.asJsonAsync();


            HttpRequest destinationRequest = unirestGetWithToken(simpleTravelApiUrl + "/airports/{key}")
                    .routeParam("key", destination)
                    .queryString(params);
            Future<HttpResponse<JsonNode>> destinationResponseFuture = destinationRequest.asJsonAsync();

            HttpResponse<JsonNode> faresResponse = faresResponseFuture.get();
            HttpResponse<JsonNode> originResponse = originResponseFuture.get();
            HttpResponse<JsonNode> destinationResponse = destinationResponseFuture.get();

            JSONObject result = faresResponse.getBody().getObject();
            result.put("origin", originResponse.getBody().getObject());
            result.put("destination", destinationResponse.getBody().getObject());

            return new ResponseEntity<>(result.toString(), HttpStatus.OK);
        };
    }

}
