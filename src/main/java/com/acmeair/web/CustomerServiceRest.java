/*******************************************************************************
* Copyright (c) 2013 IBM Corp.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

package com.acmeair.web;

import com.acmeair.securityutils.SecurityUtils;
import com.acmeair.service.CustomerService;
import com.acmeair.web.dto.AddressInfo;
import com.acmeair.web.dto.CustomerInfo;

import java.io.StringReader;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.inject.Inject;
import javax.json.Json;
import javax.json.JsonBuilderFactory;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonReader;
import javax.json.JsonReaderFactory;
import javax.ws.rs.Consumes;
import javax.ws.rs.CookieParam;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

/* microprofile-1.1 */
import org.eclipse.microprofile.config.inject.ConfigProperty;


@Path("/")
public class CustomerServiceRest {

  @Inject
  CustomerService customerService;

  @Inject
  private SecurityUtils secUtils;

  protected Logger logger = Logger.getLogger(CustomerServiceRest.class.getName());

  private static final JsonReaderFactory rfactory = Json.createReaderFactory(null);
  private static final JsonBuilderFactory bFactory = Json.createBuilderFactory(null);

  /* microprofile-1.1 */
  @Inject @ConfigProperty(name="SECURE_USER_CALLS", defaultValue="true") private Boolean SECURE_USER_CALLS;
  /*
  private static final Boolean SECURE_USER_CALLS = Boolean
      .valueOf((System.getenv("SECURE_USER_CALLS") == null) ? "true" 
          : System.getenv("SECURE_USER_CALLS"));
  */
  
  /* microprofile-1.1 */
  @Inject @ConfigProperty(name="SECURE_SERVICE_CALLS", defaultValue="false") private Boolean SECURE_SERVICE_CALLS;
  /*
  private static final Boolean SECURE_SERVICE_CALLS = Boolean
      .valueOf((System.getenv("SECURE_SERVICE_CALLS") == null) ? "false" 
          : System.getenv("SECURE_SERVICE_CALLS"));
  */
  /* cannot use injected member variables in the constructor
  static {
    System.out.println("SECURE_USER_CALLS: " + SECURE_USER_CALLS);
    System.out.println("SECURE_SERVICE_CALLS: " + SECURE_SERVICE_CALLS);
  }
  */

  /**
   * Get customer info.
   */
  @GET
  @Path("/byid/{custid}")
  @Produces("text/plain")
  public Response getCustomer(@PathParam("custid") String customerid, 
      @CookieParam("jwt_token") String jwtToken) {
    if (logger.isLoggable(Level.FINE)) {
      logger.fine("getCustomer : userid " + customerid);
    }

    try {
      // make sure the user isn't trying to update a customer other than the one
      // currently logged in
      if (SECURE_USER_CALLS && !secUtils.validateJwt(customerid, jwtToken)) {
        return Response.status(Response.Status.FORBIDDEN).build();
      }

      return Response.ok(customerService.getCustomerByUsername(customerid)).build();
      
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }

  /**
   * Update customer.
   */
  @POST
  @Path("/byid/{custid}")
  @Produces("text/plain")
  public Response putCustomer(CustomerInfo customer, @CookieParam("jwt_token") String jwtToken) {

    String username = customer.get_id();       
    
    if (SECURE_USER_CALLS && !secUtils.validateJwt(username, jwtToken)) {
      return Response.status(Response.Status.FORBIDDEN).build();
    }

    String customerFromDb = customerService
        .getCustomerByUsernameAndPassword(username, customer.getPassword());
    
    if (logger.isLoggable(Level.FINE)) {
      logger.fine("putCustomer : " + customerFromDb);
    }

    if (customerFromDb == null) {
      // either the customer doesn't exist or the password is wrong
      return Response.status(Response.Status.FORBIDDEN).build();
    }

    customerService.updateCustomer(username, customer);

    // Retrieve the latest results
    customerFromDb = customerService
        .getCustomerByUsernameAndPassword(username, customer.getPassword());
    
    return Response.ok(customerFromDb).build();
  }

  /**
   * Validate user/password.
   */
  @POST
  @Path("/validateid")
  @Consumes({ "application/x-www-form-urlencoded" })
  @Produces("application/json")
  public Response validateCustomer(@HeaderParam("acmeair-id") String headerId,
      @HeaderParam("acmeair-date") String headerDate, 
      @HeaderParam("acmeair-sig-body") String headerSigBody,
      @HeaderParam("acmeair-signature") String headerSig, @FormParam("login") String login,
      @FormParam("password") String password) {

    if (logger.isLoggable(Level.FINE)) {
      logger.fine("validateid : login " + login + " password " + password);
    }

    // verify header
    if (SECURE_SERVICE_CALLS) {
      String body = "login=" + login + "&password=" + password;
      secUtils.verifyBodyHash(body, headerSigBody);
      secUtils.verifyFullSignature("POST", "/validateid", headerId, headerDate, 
          headerSigBody, headerSig);
    }

    Boolean validCustomer = customerService.validateCustomer(login, password);

    JsonObjectBuilder job = bFactory.createObjectBuilder();
    JsonObject value = job.add("validCustomer", validCustomer).build();

    return Response.ok(value.toString()).build();
  }

  /**
   * Update reward miles.
   */
  @POST
  @Path("/updateCustomerTotalMiles/{custid}")
  @Consumes({ "application/x-www-form-urlencoded" })
  @Produces("application/json")
  public Response updateCustomerTotalMiles(@HeaderParam("acmeair-id") String headerId,
      @HeaderParam("acmeair-date") String headerDate, 
      @HeaderParam("acmeair-sig-body") String headerSigBody,
      @HeaderParam("acmeair-signature") String headerSig, 
      @PathParam("custid") String customerid,
      @FormParam("miles") Long miles) {

    try {
      if (SECURE_SERVICE_CALLS) {
        String body = "miles=" + miles;
        secUtils.verifyBodyHash(body, headerSigBody);
        secUtils.verifyFullSignature("POST", "/updateCustomerTotalMiles", 
            headerId, headerDate, headerSigBody, headerSig);
      }

      JsonReader jsonReader = rfactory.createReader(new StringReader(customerService
          .getCustomerByUsername(customerid)));
      
      JsonObject customerJson = jsonReader.readObject();
      jsonReader.close();

     
      JsonObject addressJson = customerJson.getJsonObject("address");

      String streetAddress2 = null;

      if (addressJson.get("streetAddress2") != null 
          && !addressJson.get("streetAddress2").toString().equals("null")) {
        streetAddress2 = addressJson.getString("streetAddress2");
      }
      
      AddressInfo addressInfo = new AddressInfo(addressJson.getString("streetAddress1"), 
          streetAddress2,
          addressJson.getString("city"), 
          addressJson.getString("stateProvince"),
          addressJson.getString("country"),
          addressJson.getString("postalCode"));

      Long milesUpdate = customerJson.getInt("total_miles") + miles;
      CustomerInfo customerInfo = new CustomerInfo(customerid, 
          null, 
          customerJson.getString("status"),
          milesUpdate.intValue(), 
          customerJson.getInt("miles_ytd"), 
          addressInfo, 
          customerJson.getString("phoneNumber"),
          customerJson.getString("phoneNumberType"));

      customerService.updateCustomer(customerid, customerInfo);
            
      JsonObjectBuilder job = bFactory.createObjectBuilder();
      JsonObject value = job.add("total_miles", milesUpdate).build();

      return Response.ok(value.toString()).build();

    } catch (Exception e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
      return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
    }
  }

  @GET
  public Response checkStatus() {
    return Response.ok("OK").build();

  }
}
