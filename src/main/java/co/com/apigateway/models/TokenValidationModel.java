package co.com.apigateway.models;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class TokenValidationModel {
    private boolean status;
    private String message;

    @Override
    public String toString() {
        return "{" +
                "\"status\":" + status +
                ", \"message\": \"" + message + '\"' +
                '}';
    }
}
