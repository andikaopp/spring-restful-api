package developerkeren.restful.controller;

import developerkeren.restful.entity.User;
import developerkeren.restful.model.*;
import developerkeren.restful.service.AddressService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

@RestController
public class AddressController {

    @Autowired
    private AddressService addressService;

    @PostMapping(
            path = "/api/contacts/{contactId}/addresses",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public WebResponse<AddressResponse> create(User user,
                                               @RequestBody CreateAddressRequest request,
                                               @PathVariable("contactId") String contactId){
        request.setContactId(contactId);
        AddressResponse addressResponse = addressService.create(user, request);
        return WebResponse.<AddressResponse>builder().data(addressResponse).build();
    }

    @GetMapping(
            path = "/api/contacts/{contactId}/addresses/{addressId}",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public WebResponse<AddressResponse> get(User user,
                                            @PathVariable("contactId") String contactId,
                                            @PathVariable("addressId") String addressId){
        AddressResponse addressResponse = addressService.get(user, contactId, addressId);
        return WebResponse.<AddressResponse>builder().data(addressResponse).build();
    }

    @PutMapping(
        path = "/api/contacts/{contactId}/addresses/{addressId}",
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public WebResponse<AddressResponse> update(User user,
                                               @RequestBody UpdateAddressRequest request,
                                               @PathVariable("contactId") String contactId,
                                               @PathVariable("addressId") String addressId){
        request.setContactId(contactId);
        request.setAddressId(addressId);

        AddressResponse addressResponse = addressService.update(user, request);
        return WebResponse.<AddressResponse>builder().data(addressResponse).build();
    }
}
