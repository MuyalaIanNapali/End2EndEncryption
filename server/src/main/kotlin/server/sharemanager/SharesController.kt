package server.sharemanager

import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.CrossOrigin
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.security.Principal

@RestController
@CrossOrigin
@RequestMapping(value = ["/api/v1/share"], produces = ["application/json"])
class SharesController(
    private val service: SharesService
) {
    @GetMapping
    fun getShares(principal: Principal): ResponseEntity<SharesResponse> {
        val share = service.getUserShare(principal.name)

        return ResponseEntity(share, HttpStatus.OK)
    }

    @PutMapping
    fun updateShare(
        @RequestBody @Valid share: UpdateSharesRequest,
        principal: Principal
    ): ResponseEntity<Void> {
        service.createOrUpdateUserShare(principal.name, share)
        return ResponseEntity(HttpStatus.NO_CONTENT)
    }
}